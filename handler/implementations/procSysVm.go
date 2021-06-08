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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
)

//
// /proc/sys/vm/mmap_min_addr handler
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

const (
	minOvercommitMem = 0
	maxOverCommitMem = 2
)

type ProcSysVm struct {
	domain.HandlerBase
}

var ProcSysVm_Handler = &ProcSysVm{
	domain.HandlerBase{
		Name: "ProcSysVm",
		Path: "/proc/sys/vm",
		EmuResourceMap: map[string]domain.EmuResource{
			"overcommit_memory": {Kind: domain.FileEmuResource, Mode: os.FileMode(uint32(0644))},
			"mmap_min_addr":     {Kind: domain.FileEmuResource, Mode: os.FileMode(uint32(0644))},
		},
		Type:      domain.NODE_SUBSTITUTION,
		Enabled:   true,
		Cacheable: true,
	},
}

func (h *ProcSysVm) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method for Req ID=%#x on %v handler",
		req.ID, h.Name)

	var lookupNode = filepath.Base(n.Path())

	// Return an artificial fileInfo if looked-up element matches any of the
	// emulated nodes.
	if v, ok := h.EmuResourceMap[lookupNode]; ok {
		info := &domain.FileInfo{
			Fname:    lookupNode,
			Fmode:    v.Mode,
			FmodTime: time.Now(),
		}

		return info, nil
	}

	// If looked-up element hasn't been found by now, let's look into the actual
	// sys container rootfs.
	procSysCommonHandler, ok := h.Service.FindHandler("/proc/sys/")
	if !ok {
		return nil, fmt.Errorf("No /proc/sys/ handler found")
	}

	return procSysCommonHandler.Lookup(n, req)
}

func (h *ProcSysVm) Getattr(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (*syscall.Stat_t, error) {

	logrus.Debugf("Executing GetAttr() method for Req ID=%#x on %v handler",
		req.ID, h.Name)

	return nil, nil
}

func (h *ProcSysVm) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	logrus.Debugf("Executing Open() method for Req ID=%#x on %v handler",
		req.ID, h.Name)

	name := n.Name()
	cntr := req.Container

	// Ensure operation is generated from within a registered sys container.
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return errors.New("Container not found")
	}

	switch name {
	case "overcommit_memory":
		return nil

	case "mmap_min_addr":
		return nil
	}

	procSysCommonHandler, ok := h.Service.FindHandler("/proc/sys/")
	if !ok {
		return fmt.Errorf("No /proc/sys/ handler found")
	}

	return procSysCommonHandler.Open(n, req)
}

func (h *ProcSysVm) Close(n domain.IOnodeIface) error {

	logrus.Debugf("Executing Close() method on %v handler", h.Name)

	return nil
}

func (h *ProcSysVm) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Read() method for Req ID=%#x on %v handler",
		req.ID, h.Name)

	// We are dealing with a single boolean element being read, so we can save
	// some cycles by returning right away if offset is any higher than zero.
	if req.Offset > 0 {
		return 0, io.EOF
	}

	name := n.Name()
	cntr := req.Container

	// Ensure operation is generated from within a registered sys container.
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return 0, errors.New("Container not found")
	}

	switch name {
	case "overcommit_memory":
		return readFileInt(h, n, req)

	case "mmap_min_addr":
		return readFileInt(h, n, req)
	}

	// Refer to generic handler if no node match is found above.
	procSysCommonHandler, ok := h.Service.FindHandler("/proc/sys/")
	if !ok {
		return 0, fmt.Errorf("No /proc/sys/ handler found")
	}

	return procSysCommonHandler.Read(n, req)
}

func (h *ProcSysVm) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Write() method for Req ID=%#x on %v handler",
		req.ID, h.Name)

	name := n.Name()
	cntr := req.Container

	// Ensure operation is generated from within a registered sys container.
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return 0, errors.New("Container not found")
	}

	switch name {
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
		return writeFileInt(h, n, req, 0, MaxInt, false)
	}

	// Refer to generic handler if no node match is found above.
	procSysCommonHandler, ok := h.Service.FindHandler("/proc/sys/")
	if !ok {
		return 0, fmt.Errorf("No /proc/sys/ handler found")
	}

	return procSysCommonHandler.Write(n, req)
}

func (h *ProcSysVm) ReadDirAll(
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

	var fileEntries []os.FileInfo

	// Also collect procfs entries as seen within container's namespaces.
	procSysCommonHandler, ok := h.Service.FindHandler("/proc/sys/")
	if !ok {
		return nil, fmt.Errorf("No /proc/sys/ handler found")
	}
	commonNeigh, err := procSysCommonHandler.ReadDirAll(n, req)
	if err == nil {
		for _, entry := range commonNeigh {
			fileEntries = append(fileEntries, entry)
		}
	}

	return fileEntries, nil
}

func (h *ProcSysVm) GetName() string {
	return h.Name
}

func (h *ProcSysVm) GetPath() string {
	return h.Path
}

func (h *ProcSysVm) GetEnabled() bool {
	return h.Enabled
}

func (h *ProcSysVm) GetType() domain.HandlerType {
	return h.Type
}

func (h *ProcSysVm) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *ProcSysVm) GetResourceMap() map[string]domain.EmuResource {
	return h.EmuResourceMap
}

func (h *ProcSysVm) GetResourceMutex(s string) *sync.Mutex {
	resource, ok := h.EmuResourceMap[s]
	if !ok {
		return nil
	}

	return &resource.Mutex
}

func (h *ProcSysVm) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *ProcSysVm) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
