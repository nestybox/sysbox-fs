//
// Copyright 2019-2020 Nestybox, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package implementations

import (
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/nestybox/sysbox-fs/domain"

	"github.com/sirupsen/logrus"
)

// /proc/sys common handler
//
// Handler for all non-emulated resources within the /proc/sys subtree. It does
// a simple "passthrough" of the access by entering all the namespaces of the
// process that is doing the /proc/sys access and performing that access on
// behalf of it.
//
// Note that emulated resources within /proc/sys don't go through this handler,
// but rather through their specific handlers (see handlerDB.go).
//

type ProcSysCommon struct {
	domain.HandlerBase
}

var ProcSysCommon_Handler = &ProcSysCommon{
	domain.HandlerBase{
		Name:      "ProcSysCommon",
		Path:      "/proc/sys/",
		Enabled:   true,
		Cacheable: true,
	},
}

func (h *ProcSysCommon) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method for Req ID=%#x on %v handler: %s", req.ID, h.Name, n.Path())

	// Ensure operation is generated from within a registered sys container.
	if req.Container == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return nil, errors.New("Container not found")
	}

	// Create nsenterEvent to initiate interaction with container namespaces.
	nss := h.Service.NSenterService()
	event := nss.NewEvent(
		req.Pid,
		&domain.AllNSsButMount,
		&domain.NSenterMessage{
			Type: domain.LookupRequest,
			Payload: &domain.LookupPayload{
				Entry: n.Path(),
			},
		},
		nil,
		false,
	)

	// Launch nsenter-event.
	err := nss.SendRequestEvent(event)
	if err != nil {
		return nil, err
	}

	// Obtain nsenter-event response.
	responseMsg := nss.ReceiveResponseEvent(event)
	if responseMsg.Type == domain.ErrorResponse {
		return nil, responseMsg.Payload.(error)
	}

	info := responseMsg.Payload.(domain.FileInfo)

	return info, nil
}

func (h *ProcSysCommon) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	logrus.Debugf("Executing Open() method for Req ID=%#x on %v handler", req.ID, h.Name)

	// Ensure operation is generated from within a registered sys container.
	if req.Container == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return errors.New("Container not found")
	}

	// Create nsenterEvent to initiate interaction with container namespaces.
	nss := h.Service.NSenterService()
	event := nss.NewEvent(
		req.Pid,
		&domain.AllNSsButMount,
		&domain.NSenterMessage{
			Type: domain.OpenFileRequest,
			Payload: &domain.OpenFilePayload{
				File:  n.Path(),
				Flags: strconv.Itoa(n.OpenFlags()),
				Mode:  strconv.Itoa(int(n.OpenMode())),
			},
		},
		nil,
		false,
	)

	// Launch nsenter-event.
	err := nss.SendRequestEvent(event)
	if err != nil {
		return err
	}

	// Obtain nsenter-event response.
	responseMsg := nss.ReceiveResponseEvent(event)
	if responseMsg.Type == domain.ErrorResponse {
		return responseMsg.Payload.(error)
	}

	return nil
}

func (h *ProcSysCommon) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Read() method for Req ID=%#x on %v handler", req.ID, h.Name)

	if req.Offset > 0 {
		return 0, io.EOF
	}

	name := n.Name()
	path := n.Path()

	// Ensure operation is generated from within a registered sys container.
	if req.Container == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return 0, errors.New("Container not found")
	}

	var (
		data string
		ok   bool
		err  error
	)

	prs := h.Service.ProcessService()
	process := prs.ProcessCreate(req.Pid, req.Uid, req.Gid)
	cntr := req.Container

	//
	// Caching here improves performance by avoiding dispatching the nsenter agent.  But
	// note that caching is only helping processes at the sys container level, not in inner
	// containers or unshared namespaces. To enable caching for those, we would need to
	// have a cache per each namespace and this is expensive; plus we would also need to
	// know when the namespace ceases to exist in order to destroy the cache associated
	// with it.
	//
	if h.Cacheable && domain.ProcessNsMatch(process, cntr.InitProc()) {

		// If this resource is cached, return it's data; otherwise fetch its data from the
		// host FS and store it in the cache.
		cntr.Lock()
		data, ok = cntr.Data(path, name)
		if !ok {
			data, err = h.fetchFile(n, process)
			if err != nil {
				cntr.Unlock()
				return 0, err
			}

			cntr.SetData(path, name, data)
		}
		cntr.Unlock()
	} else {
		data, err = h.fetchFile(n, process)
		if err != nil {
			return 0, err
		}
	}

	data += "\n"

	return copyResultBuffer(req.Data, []byte(data))
}

func (h *ProcSysCommon) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Write() method for Req ID=%#x on %v handler", req.ID, h.Name)

	name := n.Name()
	path := n.Path()

	// Ensure operation is generated from within a registered sys container.
	if req.Container == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return 0, errors.New("Container not found")
	}

	newContent := strings.TrimSpace(string(req.Data))

	prs := h.Service.ProcessService()
	process := prs.ProcessCreate(req.Pid, req.Uid, req.Gid)
	cntr := req.Container

	// If caching is enabled, store the data in the cache and do a write-through to the
	// host FS. Otherwise just do the write-through.
	if h.Cacheable && domain.ProcessNsMatch(process, cntr.InitProc()) {

		cntr.Lock()
		if err := h.pushFile(n, process, newContent); err != nil {
			cntr.Unlock()
			return 0, err
		}
		cntr.SetData(path, name, newContent)
		cntr.Unlock()

	} else {
		if err := h.pushFile(n, process, newContent); err != nil {
			return 0, err
		}
	}

	return len(req.Data), nil
}

func (h *ProcSysCommon) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	logrus.Debugf("Executing ReadDirAll() method for Req ID=%#x on %v handler",
		req.ID, h.Name)

	// Ensure operation is generated from within a registered sys container.
	if req.Container == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return nil, errors.New("Container not found")
	}

	// Create nsenterEvent to initiate interaction with container namespaces.
	nss := h.Service.NSenterService()
	event := nss.NewEvent(
		req.Pid,
		&domain.AllNSsButMount,
		&domain.NSenterMessage{
			Type: domain.ReadDirRequest,
			Payload: &domain.ReadDirPayload{
				Dir: n.Path(),
			},
		},
		nil,
		false,
	)

	// Launch nsenter-event.
	err := nss.SendRequestEvent(event)
	if err != nil {
		return nil, err
	}

	// Obtain nsenter-event response.
	responseMsg := nss.ReceiveResponseEvent(event)
	if responseMsg.Type == domain.ErrorResponse {
		return nil, responseMsg.Payload.(error)
	}

	var osFileEntries = make([]os.FileInfo, 0)

	// Transform event-response payload into a FileInfo slice. Notice that to
	// convert []T1 struct to a []T2 one, we must iterate through each element
	// and do the conversion one element at a time.
	dirEntries := responseMsg.Payload.([]domain.FileInfo)
	for _, v := range dirEntries {
		osFileEntries = append(osFileEntries, v)
	}

	return osFileEntries, nil
}

func (h *ProcSysCommon) Setattr(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	logrus.Debugf("Executing Setattr() method for Req ID=%#x on %v handler", req.ID, h.Name)

	// Ensure operation is generated from within a registered sys container.
	if req.Container == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return errors.New("Container not found")
	}

	// Create nsenterEvent to initiate interaction with container namespaces.
	nss := h.Service.NSenterService()
	event := nss.NewEvent(
		req.Pid,
		&domain.AllNSsButMount,
		&domain.NSenterMessage{
			Type: domain.OpenFileRequest,
			Payload: &domain.OpenFilePayload{
				File:  n.Path(),
				Flags: strconv.Itoa(n.OpenFlags()),
				Mode:  strconv.Itoa(int(n.OpenMode())),
			},
		},
		nil,
		false,
	)

	// Launch nsenter-event.
	err := nss.SendRequestEvent(event)
	if err != nil {
		return err
	}

	// Obtain nsenter-event response.
	responseMsg := nss.ReceiveResponseEvent(event)
	if responseMsg.Type == domain.ErrorResponse {
		return responseMsg.Payload.(error)
	}

	return nil
}

// Auxiliary method to fetch the content of any given file within a container.
func (h *ProcSysCommon) fetchFile(
	n domain.IOnodeIface,
	process domain.ProcessIface) (string, error) {

	// Create nsenterEvent to initiate interaction with container namespaces.
	nss := h.Service.NSenterService()
	event := nss.NewEvent(
		process.Pid(),
		&domain.AllNSsButMount,
		&domain.NSenterMessage{
			Type: domain.ReadFileRequest,
			Payload: &domain.ReadFilePayload{
				File: n.Path(),
			},
		},
		nil,
		false,
	)

	// Launch nsenter-event to obtain file state within container
	// namespaces.
	err := nss.SendRequestEvent(event)
	if err != nil {
		return "", err
	}

	// Obtain nsenter-event response.
	responseMsg := nss.ReceiveResponseEvent(event)
	if responseMsg.Type == domain.ErrorResponse {
		return "", responseMsg.Payload.(error)
	}

	info := responseMsg.Payload.(string)

	return info, nil
}

// Auxiliary method to inject content into any given file within a container.
func (h *ProcSysCommon) pushFile(
	n domain.IOnodeIface,
	process domain.ProcessIface,
	s string) error {

	// Create nsenterEvent to initiate interaction with container namespaces.
	nss := h.Service.NSenterService()
	event := nss.NewEvent(
		process.Pid(),
		&domain.AllNSsButMount,
		&domain.NSenterMessage{
			Type: domain.WriteFileRequest,
			Payload: &domain.WriteFilePayload{
				File:    n.Path(),
				Content: s,
			},
		},
		nil,
		false,
	)

	// Launch nsenter-event to write file state within container
	// namespaces.
	err := nss.SendRequestEvent(event)
	if err != nil {
		return err
	}

	// Obtain nsenter-event response.
	responseMsg := nss.ReceiveResponseEvent(event)
	if responseMsg.Type == domain.ErrorResponse {
		return responseMsg.Payload.(error)
	}

	return nil
}

func (h *ProcSysCommon) GetName() string {
	return h.Name
}

func (h *ProcSysCommon) GetPath() string {
	return h.Path
}

func (h *ProcSysCommon) GetEnabled() bool {
	return h.Enabled
}

func (h *ProcSysCommon) GetType() domain.HandlerType {
	return h.Type
}

func (h *ProcSysCommon) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *ProcSysCommon) GetResourceMap() map[string]domain.EmuResource {
	return h.EmuResourceMap
}

func (h *ProcSysCommon) GetResourceMutex(s string) *sync.Mutex {
	resource, ok := h.EmuResourceMap[s]
	if !ok {
		return nil
	}

	return &resource.Mutex
}

func (h *ProcSysCommon) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *ProcSysCommon) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
