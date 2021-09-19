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
	"sync"
	"syscall"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"

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

	var (
		sz  int
		err error
	)

	logrus.Debugf("Executing Read() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	path := n.Path()
	cntr := req.Container

	prs := h.Service.ProcessService()
	process := prs.ProcessCreate(req.Pid, req.Uid, req.Gid)

	//
	// The passthrough driver is slow because it must spawn a process that enters
	// the container's namespaces (i.e., the nsenter agent) and read the data
	// from there. To improve things, we cache the data on the first access to
	// avoid dispatching the nsenter agent on subsequent accesess.
	//
	// A couple of caveats on the caching:
	//
	// 1) Caching is only done for processes at the sys container level, not in
	// inner containers or inner unshared namespaces. To enable caching for
	// those, we would need to have a cache per each namespace set (since the
	// values under /proc/sys depend on the namespaces that the process belongs
	// to). This would be expensive and would also require Sysbox to know when
	// the namespace ceases to exist in order to destroy the cache associated
	// with it.
	//
	// 2) As an optimization, we fetch data from the container's filesystem only
	// when the req.Offset is 0. For req.Offset > 0, we assume that the data is
	// cached already. Without this optimization, we will likely go through
	// fetchFile() twice for each read: one with req.Offset 0, and one at
	// req.Offset X, where X is the number of bytes of the resource being
	// read. That is, the handler's Read() method is normally invoked twice: the
	// first read returns X bytes, the second read returns 0 bytes.

	if domain.ProcessNsMatch(process, cntr.InitProc()) {

		cntr.Lock()

		// Check the data cache
		sz, err = cntr.Data(path, req.Offset, &req.Data)
		if err != nil && err != io.EOF {
			cntr.Unlock()
			return 0, fuse.IOerror{Code: syscall.EINVAL}
		}

		if req.Offset == 0 && sz == 0 && err == io.EOF {

			// Resource is not cached, read it from the filesystem.
			sz, err = h.fetchFile(process, n, req.Offset, &req.Data)
			if err != nil {
				cntr.Unlock()
				return 0, fuse.IOerror{Code: syscall.EINVAL}
			}

			if sz == 0 {
				cntr.Unlock()
				return 0, nil
			}

			err = cntr.SetData(path, req.Offset, req.Data)
			if err != nil {
				cntr.Unlock()
				return 0, fuse.IOerror{Code: syscall.EINVAL}
			}
		}

		cntr.Unlock()

	} else {
		sz, err = h.fetchFile(process, n, req.Offset, &req.Data)
		if err != nil {
			return 0, fuse.IOerror{Code: syscall.EINVAL}
		}
	}

	return sz, nil
}

func (h *PassThrough) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	var (
		len int
		err error
	)

	resource := n.Name()

	logrus.Debugf("Executing Write() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	path := n.Path()
	cntr := req.Container

	prs := h.Service.ProcessService()
	process := prs.ProcessCreate(req.Pid, req.Uid, req.Gid)

	if len, err = h.pushFile(process, n, req.Offset, req.Data); err != nil {
		return 0, err
	}

	// If the write comes from a process inside the sys container's namespaces,
	// (not in inner containers or unshared namespaces) then cache the data.
	// See explanation in Read() method above.

	if domain.ProcessNsMatch(process, cntr.InitProc()) {
		cntr.Lock()
		err = cntr.SetData(path, req.Offset, req.Data)
		if err != nil {
			cntr.Unlock()
			return 0, fuse.IOerror{Code: syscall.EINVAL}
		}
		cntr.Unlock()
	}

	return len, nil
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
	process domain.ProcessIface,
	n domain.IOnodeIface,
	offset int64,
	data *[]byte) (int, error) {

	// Create nsenterEvent to initiate interaction with container namespaces.
	nss := h.Service.NSenterService()

	event := nss.NewEvent(
		process.Pid(),
		&domain.AllNSsButMount,
		&domain.NSenterMessage{
			Type: domain.ReadFileRequest,
			Payload: &domain.ReadFilePayload{
				File:   n.Path(),
				Offset: offset,
				Len:    len(*data),
			},
		},
		nil,
		false,
	)

	// Launch nsenter-event to obtain file state within container
	// namespaces.
	err := nss.SendRequestEvent(event)
	if err != nil {
		return 0, err
	}

	// Obtain nsenter-event response.
	responseMsg := nss.ReceiveResponseEvent(event)
	if responseMsg.Type == domain.ErrorResponse {
		return 0, responseMsg.Payload.(error)
	}

	*data = responseMsg.Payload.([]byte)

	return len(*data), nil
}

// Auxiliary method to inject content into any given file within a container.
func (h *PassThrough) pushFile(
	process domain.ProcessIface,
	n domain.IOnodeIface,
	offset int64,
	data []byte) (int, error) {

	// Create nsenterEvent to initiate interaction with container namespaces.
	nss := h.Service.NSenterService()

	event := nss.NewEvent(
		process.Pid(),
		&domain.AllNSsButMount,
		&domain.NSenterMessage{
			Type: domain.WriteFileRequest,
			Payload: &domain.WriteFilePayload{
				File:   n.Path(),
				Offset: offset,
				Data:   data,
			},
		},
		nil,
		false,
	)

	// Launch nsenter-event to write file state within container
	// namespaces.
	err := nss.SendRequestEvent(event)
	if err != nil {
		return 0, err
	}

	// Obtain nsenter-event response.
	responseMsg := nss.ReceiveResponseEvent(event)
	if responseMsg.Type == domain.ErrorResponse {
		return 0, responseMsg.Payload.(error)
	}

	return len(data), nil
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
