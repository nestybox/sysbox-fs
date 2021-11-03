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
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/nestybox/sysbox-fs/domain"

	"github.com/sirupsen/logrus"
)

//
// Pass-through handler
//
// Handler for all non-emulated resources. It does a simple "passthrough" of the
// access by entering all the namespaces of the process that is doing the I/O
// operation and performs this one on behalf of it.
//
// Currently, this handler serves non-emulated resources within the /proc/sys
// subtree, but there's nothing specific to this path in this handler's
// implementation (see that the Path attribute is set to "*"), so this one could
// be utilized for pass-through operations in other subtrees too.
//

type PassThrough struct {
	domain.HandlerBase
}

var PassThrough_Handler = &PassThrough{
	domain.HandlerBase{
		Name:    "PassThrough",
		Path:    "*",
		Enabled: true,
	},
}

func (h *PassThrough) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

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

func (h *PassThrough) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	logrus.Debugf("Executing Open() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

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

func (h *PassThrough) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	var resource = n.Name()

	logrus.Debugf("Executing Read() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	if req.Offset > 0 {
		return 0, io.EOF
	}

	var (
		data string
		ok   bool
		err  error
	)

	path := n.Path()
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
	if domain.ProcessNsMatch(process, cntr.InitProc()) {

		// If this resource is cached, return it's data; otherwise fetch its data from the
		// host FS and store it in the cache.
		cntr.Lock()
		data, ok = cntr.Data(path, resource)
		if !ok {
			data, err = h.fetchFile(n, process)
			if err != nil {
				cntr.Unlock()
				return 0, err
			}

			if !req.NoCache {
				cntr.SetData(path, resource, data)
			}

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

func (h *PassThrough) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	var resource = n.Name()

	logrus.Debugf("Executing Write() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	path := n.Path()
	cntr := req.Container

	var newContent string

	if req.Opaque {
		newContent = string(req.Data)
	} else {
		newContent = strings.TrimSpace(string(req.Data))
	}

	prs := h.Service.ProcessService()
	process := prs.ProcessCreate(req.Pid, req.Uid, req.Gid)

	// If write op is originated by a process within a registered sys-container
	// (it fully matches its namespaces) then store the data in the cache and do
	// a write-through to the host FS. Otherwise just do the write-through.
	if domain.ProcessNsMatch(process, cntr.InitProc()) {
		cntr.Lock()
		if err := h.pushFile(n, process, newContent); err != nil {
			cntr.Unlock()
			return 0, err
		}

		if !req.NoCache {
			cntr.SetData(path, resource, newContent)
		}
		cntr.Unlock()

	} else {
		if err := h.pushFile(n, process, newContent); err != nil {
			return 0, err
		}
	}

	return len(req.Data), nil
}

func (h *PassThrough) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	logrus.Debugf("Executing ReadDirAll() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

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

func (h *PassThrough) Setattr(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	logrus.Debugf("Executing Setattr() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

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
func (h *PassThrough) fetchFile(
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
func (h *PassThrough) pushFile(
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

func (h *PassThrough) GetName() string {
	return h.Name
}

func (h *PassThrough) GetPath() string {
	return h.Path
}

func (h *PassThrough) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *PassThrough) GetEnabled() bool {
	return h.Enabled
}

func (h *PassThrough) SetEnabled(b bool) {
	h.Enabled = b
}

func (h *PassThrough) GetResourcesList() []string {

	var resources []string

	for resourceKey, resource := range h.EmuResourceMap {
		resource.Mutex.Lock()
		if !resource.Enabled {
			resource.Mutex.Unlock()
			continue
		}
		resource.Mutex.Unlock()

		resources = append(resources, filepath.Join(h.GetPath(), resourceKey))
	}

	return resources
}

func (h *PassThrough) GetResourceMutex(n domain.IOnodeIface) *sync.Mutex {
	resource, ok := h.EmuResourceMap[n.Name()]
	if !ok {
		return nil
	}

	return &resource.Mutex
}

func (h *PassThrough) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
