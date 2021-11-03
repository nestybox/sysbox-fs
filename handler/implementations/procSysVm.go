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
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
)

//
// /proc/sys/vm handler
//
// Emulated resources:
//
// * /proc/sys/vm/mmap_min_addr
//
// Documentation: This file indicates the amount of address space which a user
// process will be restricted from mmapping. Since kernel null dereference bugs
// could accidentally operate based on the information in the first couple of
// pages of memory userspace processes should not be allowed to write to them.
//
// By default this value is set to 0 and no protections will be enforced by the
// security module. Setting this value to something like 64k will allow the vast
// majority of applications to work correctly and provide defense in depth
// against future potential kernel bugs.
//
// Note: As this is a system-wide attribute, changes will be only made
// superficially (at sys-container level). IOW, the host FS value will be left
// untouched.
//
// * /proc/sys/vm/overcommit_memory
//

const (
	minOvercommitMem = 0
	maxOverCommitMem = 2
)

type ProcSysVm struct {
	domain.HandlerBase
}

var ProcSysVm_Handler = &ProcSysVm{
	domain.HandlerBase{
		Name:    "ProcSysVm",
		Path:    "/proc/sys/vm",
		Enabled: true,
		EmuResourceMap: map[string]*domain.EmuResource{
			"overcommit_memory": {
				Kind:    domain.FileEmuResource,
				Mode:    os.FileMode(uint32(0644)),
				Enabled: true,
			},
			"mmap_min_addr": {
				Kind:    domain.FileEmuResource,
				Mode:    os.FileMode(uint32(0644)),
				Enabled: true,
			},
		},
	},
}

func (h *ProcSysVm) Lookup(
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
		}

		return info, nil
	}

	// If looked-up element hasn't been found by now, let's look into the actual
	// sys container rootfs.
	return h.Service.GetPassThroughHandler().Lookup(n, req)
}

func (h *ProcSysVm) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	var resource = n.Name()

	logrus.Debugf("Executing Open() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	switch resource {
	case "overcommit_memory":
		return nil

	case "mmap_min_addr":
		return nil
	}

	return h.Service.GetPassThroughHandler().Open(n, req)
}

func (h *ProcSysVm) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	var resource = n.Name()

	logrus.Debugf("Executing Read() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	// We are dealing with a single boolean element being read, so we can save
	// some cycles by returning right away if offset is any higher than zero.
	if req.Offset > 0 {
		return 0, io.EOF
	}

	switch resource {
	case "overcommit_memory":
		return readFileInt(h, n, req)

	case "mmap_min_addr":
		return readFileInt(h, n, req)
	}

	// Refer to generic handler if no node match is found above.
	return h.Service.GetPassThroughHandler().Read(n, req)
}

func (h *ProcSysVm) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	var resource = n.Name()

	logrus.Debugf("Executing Write() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	switch resource {
	case "overcommit_memory":
		// Ensure that only proper values are allowed as per this resource semantics:
		//
		// 0: Kernel is free to overcommit memory (this is the default), a heuristic
		//    algorithm is applied to figure out if enough memory is available.
		// 1: Kernel will always overcommit memory, and never check if enough memory
		//    is available. This increases the risk of out-of-memory situations, but
		//    also improves memory-intensive workloads.
		// 2: Kernel will not overcommit memory, and only allocate as much memory as
		//    defined in overcommit_ratio.
		return writeFileInt(h, n, req, minOvercommitMem, maxOverCommitMem, false)

	case "mmap_min_addr":
		return writeFileInt(h, n, req, 0, math.MaxInt64, false)
	}

	// Refer to generic handler if no node match is found above.
	return h.Service.GetPassThroughHandler().Write(n, req)
}

func (h *ProcSysVm) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	logrus.Debugf("Executing ReadDirAll() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	// Return all entries as seen within container's namespaces.
	return h.Service.GetPassThroughHandler().ReadDirAll(n, req)
}

func (h *ProcSysVm) GetName() string {
	return h.Name
}

func (h *ProcSysVm) GetPath() string {
	return h.Path
}

func (h *ProcSysVm) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *ProcSysVm) GetEnabled() bool {
	return h.Enabled
}

func (h *ProcSysVm) SetEnabled(b bool) {
	h.Enabled = b
}

func (h *ProcSysVm) GetResourcesList() []string {

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

func (h *ProcSysVm) GetResourceMutex(n domain.IOnodeIface) *sync.Mutex {
	resource, ok := h.EmuResourceMap[n.Name()]
	if !ok {
		return nil
	}

	return &resource.Mutex
}

func (h *ProcSysVm) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
