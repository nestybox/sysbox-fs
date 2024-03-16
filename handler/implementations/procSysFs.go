//
// Copyright 2019-2023 Nestybox, Inc.
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
// /proc/sys/fs handler
//
// Emulated resources:
//
// * /proc/sys/fs/file-max
// * /proc/sys/fs/nr_open
// * /proc/sys/fs/protected_hardlinks
// * /proc/sys/fs/protected_symlinks
//

const (
	minProtectedSymlinksVal = 0
	maxProtectedSymlinksVal = 1
)

const (
	minProtectedHardlinksVal = 0
	maxProtectedHardlinksVal = 1
)

type ProcSysFs struct {
	domain.HandlerBase
}

var ProcSysFs_Handler = &ProcSysFs{
	domain.HandlerBase{
		Name:    "ProcSysFs",
		Path:    "/proc/sys/fs",
		Enabled: true,
		EmuResourceMap: map[string]*domain.EmuResource{
			"file-max": {
				Kind:    domain.FileEmuResource,
				Mode:    os.FileMode(uint32(0644)),
				Enabled: true,
				Size:    1024,
			},
			"nr_open": {
				Kind:    domain.FileEmuResource,
				Mode:    os.FileMode(uint32(0644)),
				Enabled: true,
				Size:    1024,
			},
			"protected_hardlinks": {
				Kind:    domain.FileEmuResource,
				Mode:    os.FileMode(uint32(0600)),
				Enabled: true,
				Size:    1024,
			},
			"protected_symlinks": {
				Kind:    domain.FileEmuResource,
				Mode:    os.FileMode(uint32(0600)),
				Enabled: true,
				Size:    1024,
			},
		},
	},
}

func (h *ProcSysFs) Lookup(
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
	// sys container rootfs.
	return h.Service.GetPassThroughHandler().Lookup(n, req)
}

func (h *ProcSysFs) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	var resource = n.Name()

	logrus.Debugf("Executing Open() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	switch resource {
	case "file-max":
		return nil

	case "nr_open":
		return nil

	case "protected_hardlinks":
		return nil

	case "protected_symlinks":
		return nil
	}

	return h.Service.GetPassThroughHandler().Open(n, req)
}

func (h *ProcSysFs) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	var resource = n.Name()

	logrus.Debugf("Executing Read() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	switch resource {
	case "file-max":
		return readCntrData(h, n, req)

	case "nr_open":
		return readCntrData(h, n, req)

	case "protected_hardlinks":
		return readCntrData(h, n, req)

	case "protected_symlinks":
		return readCntrData(h, n, req)
	}

	// Refer to generic handler if no node match is found above.
	return h.Service.GetPassThroughHandler().Read(n, req)
}

func (h *ProcSysFs) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	var resource = n.Name()

	logrus.Debugf("Executing Write() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	switch resource {
	case "file-max":
		return writeCntrData(h, n, req, writeMaxIntToFs)

	case "nr_open":
		return writeCntrData(h, n, req, writeMaxIntToFs)

	case "protected_hardlinks":
		if !checkIntRange(req.Data, minProtectedHardlinksVal, maxProtectedHardlinksVal) {
			return 0, fuse.IOerror{Code: syscall.EINVAL}
		}
		return writeCntrData(h, n, req, nil)

	case "protected_symlinks":
		if !checkIntRange(req.Data, minProtectedSymlinksVal, maxProtectedSymlinksVal) {
			return 0, fuse.IOerror{Code: syscall.EINVAL}
		}
		return writeCntrData(h, n, req, nil)
	}

	// Refer to generic handler if no node match is found above.
	return h.Service.GetPassThroughHandler().Write(n, req)
}

func (h *ProcSysFs) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	logrus.Debugf("Executing ReadDirAll() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	// Return all entries as seen within container's namespaces.
	return h.Service.GetPassThroughHandler().ReadDirAll(n, req)
}

func (h *ProcSysFs) ReadLink(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (string, error) {

	logrus.Debugf("Executing ReadLink() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	return h.Service.GetPassThroughHandler().ReadLink(n, req)
}

func (h *ProcSysFs) GetName() string {
	return h.Name
}

func (h *ProcSysFs) GetPath() string {
	return h.Path
}

func (h *ProcSysFs) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *ProcSysFs) GetEnabled() bool {
	return h.Enabled
}

func (h *ProcSysFs) SetEnabled(b bool) {
	h.Enabled = b
}

func (h *ProcSysFs) GetResourcesList() []string {

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

func (h *ProcSysFs) GetResourceMutex(n domain.IOnodeIface) *sync.Mutex {
	resource, ok := h.EmuResourceMap[n.Name()]
	if !ok {
		return nil
	}

	return &resource.Mutex
}

func (h *ProcSysFs) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
