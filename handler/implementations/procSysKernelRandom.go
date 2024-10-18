//
// Copyright 2019-2024 Nestybox, Inc.
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
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
)

//
// /proc/sys/kernel/random handler
//
// Emulated resources:
//
// * /proc/sys/kernel/random/uuid
//
// Documentation: a UUID generated every time this is retrieved (this can thus
// be used to generate UUIDs at will). It's emulated here because for some
// unknown reason the kernel returns the same value when this is read from
// inside a Sysbox container.
//

type ProcSysKernelRandom struct {
	domain.HandlerBase
}

var ProcSysKernelRandom_Handler = &ProcSysKernelRandom{
	domain.HandlerBase{
		Name:    "ProcSysKernelRandom",
		Path:    "/proc/sys/kernel/random",
		Enabled: true,
		EmuResourceMap: map[string]*domain.EmuResource{
			"uuid": {
				Kind:    domain.FileEmuResource,
				Mode:    os.FileMode(uint32(0444)),
				Enabled: true,
				Size:    1024,
			},
		},
	},
}

func (h *ProcSysKernelRandom) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	var resource = n.Name()

	logrus.Debugf("Executing Lookup() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	// Return an artificial fileInfo if looked-up element matches any of the
	// emulated nodes.
	if v, ok := h.EmuResourceMap[resource]; ok {
		info := &domain.FileInfo{
			Fname:    resource,
			Fmode:    v.Mode,
			FmodTime: time.Now(),
			Fsize:    v.Size,
		}

		return info, nil
	}

	// If looked-up element hasn't been found by now, let's look into the actual
	// container rootfs.
	return h.Service.GetPassThroughHandler().Lookup(n, req)
}

func (h *ProcSysKernelRandom) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (bool, error) {

	return false, nil
}

func (h *ProcSysKernelRandom) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	var resource = n.Name()

	logrus.Debugf("Executing Read() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	switch resource {
	case "uuid":
		// Read /proc/sys/kernel/uuid from the kernel
		sz, err := readFs(h, n, req.Offset, &req.Data)
		if err != nil && err != io.EOF {
			return 0, fuse.IOerror{Code: syscall.EINVAL}
		}
		if sz == 0 && err == io.EOF {
			return 0, nil
		}
		return sz, nil
	}

	// Refer to generic handler if no node match is found above.
	return h.Service.GetPassThroughHandler().Read(n, req)
}

func (h *ProcSysKernelRandom) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	var resource = n.Name()

	logrus.Debugf("Executing Write() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	switch resource {
	case "uuid":
		// uuid is read-only
		return 0, fuse.IOerror{Code: syscall.EPERM}
	}

	// Refer to generic handler if no node match is found above.
	return h.Service.GetPassThroughHandler().Write(n, req)
}

func (h *ProcSysKernelRandom) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	logrus.Debugf("Executing ReadDirAll() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	// Return all entries as seen within container's namespaces.
	return h.Service.GetPassThroughHandler().ReadDirAll(n, req)
}

func (h *ProcSysKernelRandom) ReadLink(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (string, error) {

	logrus.Debugf("Executing ReadLink() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	return h.Service.GetPassThroughHandler().ReadLink(n, req)
}

func (h *ProcSysKernelRandom) GetName() string {
	return h.Name
}

func (h *ProcSysKernelRandom) GetPath() string {
	return h.Path
}

func (h *ProcSysKernelRandom) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *ProcSysKernelRandom) GetEnabled() bool {
	return h.Enabled
}

func (h *ProcSysKernelRandom) SetEnabled(b bool) {
	h.Enabled = b
}

func (h *ProcSysKernelRandom) GetResourcesList() []string {

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

func (h *ProcSysKernelRandom) GetResourceMutex(n domain.IOnodeIface) *sync.Mutex {
	resource, ok := h.EmuResourceMap[n.Name()]
	if !ok {
		return nil
	}

	return &resource.Mutex
}

func (h *ProcSysKernelRandom) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
