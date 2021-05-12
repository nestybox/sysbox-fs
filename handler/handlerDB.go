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

package handler

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/handler/implementations"

	iradix "github.com/hashicorp/go-immutable-radix"
)

//
// Slice of sysbox-fs' default handlers. Please keep me alphabetically
// ordered.
//
var DefaultHandlers = []domain.HandlerIface{
	implementations.Root_Handler,                                   // /
	implementations.ProcSys_Handler,                                // /proc/sys
	implementations.ProcSysCommon_Handler,                          // /proc/sys/
	implementations.ProcSwaps_Handler,                              // /proc/swaps
	implementations.ProcUptime_Handler,                             // /proc/uptime
	implementations.ProcSysFs_Handler,                              // /proc/sys/fs
	implementations.ProcSysKernel_Handler,                          // /proc/sys/kernel
	implementations.ProcSysKernelYamaPtrace_Handler,                // /proc/sys/kernel/yama/ptrace_scope
	implementations.ProcSysNetCore_Handler,                         // /proc/sys/net/core
	implementations.ProcSysNetIpv4Vs_Handler,                       // /proc/sys/net/ipv4/vs
	implementations.ProcSysNetIpv4Neigh_Handler,                    // /proc/sys/net/ipv4/neigh
	implementations.ProcSysNetNetfilter_Handler,                    // /proc/sys/net/netfilter
	implementations.ProcSysNetUnix_Handler,                         // /proc/sys/net/unix
	implementations.ProcSysVm_Handler,                              // /proc/sys/vm
	implementations.SysDevicesVirtualDmiIdProductUuid_Handler,      // /sys/devices/virtual/dmi/id/product_uuid
	implementations.SysModuleNfconntrackParametersHashsize_Handler, // /sys/module/nf_conntrack/parameters/hashsize
}

type handlerService struct {
	sync.RWMutex

	// Map to store association between handler's path (key) and the handler
	// object (value).
	handlerDB map[string]domain.HandlerIface

	// Radix-tree indexed by node FS path. Tree serves as an ordered DB where to
	// keep track of the association between resources being emulated, and its
	// matching handler object, which ultimately defines the emulation approach
	// to execute for every sysbox-fs' emulated node.
	handlerTree *iradix.Tree

	// Pointer to the service providing container-state storage functionality.
	css domain.ContainerStateServiceIface

	// Pointer to the service providing nsenter (rexec) capabilities.
	nss domain.NSenterServiceIface

	// Pointer to the service providing process-handling functionality.
	prs domain.ProcessServiceIface

	// Pointer to the service providing file-system I/O capabilities.
	ios domain.IOServiceIface

	// Represents the user-namespace inode of the host's true-root.
	hostUserNsInode domain.Inode

	// Handler i/o errors should be obviated if this flag is enabled (testing
	// purposes).
	ignoreErrors bool
}

// HandlerService constructor.
func NewHandlerService() domain.HandlerServiceIface {

	return &handlerService{}
}

func (hs *handlerService) Setup(
	hdlrs []domain.HandlerIface,
	ignoreErrors bool,
	css domain.ContainerStateServiceIface,
	nss domain.NSenterServiceIface,
	prs domain.ProcessServiceIface,
	ios domain.IOServiceIface) {

	hs.css = css
	hs.nss = nss
	hs.prs = prs
	hs.ios = ios
	hs.ignoreErrors = ignoreErrors

	hs.handlerTree = iradix.New()
	if hs.handlerTree == nil {
		logrus.Fatalf("Unable to allocate handler radix-tree")
	}

	// Register all handlers declared as 'enabled'.
	for _, h := range hdlrs {
		if h.GetEnabled() {
			hs.RegisterHandler(h)
		}
	}

	// Obtain user-ns inode corresponding to sysbox-fs.
	hostUserNsInode, err := hs.FindUserNsInode(uint32(os.Getpid()))
	if err != nil {
		logrus.Fatalf("Invalid init user-namespace found")
	}
	hs.hostUserNsInode = hostUserNsInode
}

func (hs *handlerService) RegisterHandler(h domain.HandlerIface) error {
	hs.Lock()

	name := h.GetName()
	path := h.GetPath()

	if _, ok := hs.handlerTree.Get([]byte(path)); ok {
		hs.Unlock()
		logrus.Errorf("Handler %v already registered", name)
		return errors.New("Handler already registered")
	}

	h.SetService(hs)

	tree, _, ok := hs.handlerTree.Insert([]byte(path), h)
	if ok {
		hs.Unlock()
		logrus.Errorf("Handler %v already registered", name)
		return errors.New("Handler already registered")
	}
	hs.handlerTree = tree
	hs.Unlock()

	return nil
}

func (hs *handlerService) UnregisterHandler(h domain.HandlerIface) error {
	hs.Lock()

	name := h.GetName()
	path := h.GetPath()

	if _, ok := hs.handlerTree.Get([]byte(path)); !ok {
		hs.Unlock()
		logrus.Errorf("Handler %v not previously registered", name)
		return errors.New("Handler not previously registered")
	}

	hs.handlerTree, _, _ = hs.handlerTree.Delete([]byte(path))
	hs.Unlock()

	return nil
}

func (hs *handlerService) LookupHandler(
	i domain.IOnodeIface) (domain.HandlerIface, bool) {

	hs.RLock()
	defer hs.RUnlock()

	var (
		h       domain.HandlerIface
		path    string
		pathDir string
	)

	path = i.Path()
	pathDir = filepath.Dir(path)

	for {

		// Iterate the handler's radix-tree looking for the handler that better
		// match the fs node being operated on.
		_, node, ok := hs.handlerTree.Root().LongestPrefix([]byte(path))
		if !ok {
			return nil, false
		}

		h = node.(domain.HandlerIface)

		// Stop iteration if a handler is found that fully matches the path of the
		// node being operated on (e.g., fs node: /proc/sys, handler: /proc/sys).
		if path == h.GetPath() {
			break
		}

		// Repeat the radix-tree iteration if the found handler doesn't truly
		// represent the node in question. This is a corner-case scenario that
		// should be very seldomly reproduced (e.g., fs node /proc/sys/kernel/panic_*,
		// handler: /proc/sys/kernel/panic). In most cases we will only do one
		// radix-tree iteration.
		currPathDir := filepath.Dir(h.GetPath())
		if currPathDir == pathDir && currPathDir != "/" {
			prevPathBase := filepath.Base(path)
			currPathBase := filepath.Base(h.GetPath())

			if strings.HasPrefix(prevPathBase, currPathBase) {
				path = currPathDir
				pathDir = filepath.Dir(currPathDir)
				continue
			}
		}

		break
	}

	return h, true
}

func (hs *handlerService) FindHandler(s string) (domain.HandlerIface, bool) {

	hs.RLock()
	defer hs.RUnlock()

	h, ok := hs.handlerTree.Get([]byte(s))
	if !ok {
		return nil, false
	}

	return h.(domain.HandlerIface), true
}

func (hs *handlerService) EnableHandler(h domain.HandlerIface) error {
	hs.Lock()

	name := h.GetName()
	path := h.GetPath()

	if _, ok := hs.handlerDB[path]; !ok {
		hs.Unlock()
		logrus.Errorf("Handler %v not found", name)
		return errors.New("Handler not found")
	}

	h.SetEnabled(true)
	hs.Unlock()

	return nil
}

func (hs *handlerService) DisableHandler(h domain.HandlerIface) error {
	hs.Lock()

	name := h.GetName()
	path := h.GetPath()

	if _, ok := hs.handlerDB[path]; !ok {
		hs.Unlock()
		logrus.Errorf("Handler %v not found", name)
		return errors.New("Handler not found")
	}

	h.SetEnabled(false)
	hs.Unlock()

	return nil
}

func (hs *handlerService) HandlerDB() *iradix.Tree {
	return hs.handlerTree
}

func (hs *handlerService) StateService() domain.ContainerStateServiceIface {
	return hs.css
}

func (hs *handlerService) SetStateService(css domain.ContainerStateServiceIface) {
	hs.css = css
}

func (hs *handlerService) NSenterService() domain.NSenterServiceIface {
	return hs.nss
}

func (hs *handlerService) ProcessService() domain.ProcessServiceIface {
	return hs.prs
}

func (hs *handlerService) IOService() domain.IOServiceIface {
	return hs.ios
}

func (hs *handlerService) IgnoreErrors() bool {
	return hs.ignoreErrors
}

//
// Auxiliary methods
//

func (hs *handlerService) HostUserNsInode() domain.Inode {
	return hs.hostUserNsInode
}

func (hs *handlerService) FindUserNsInode(pid uint32) (domain.Inode, error) {
	process := hs.prs.ProcessCreate(pid, 0, 0)

	userNsInode, err := process.UserNsInode()
	if err != nil {
		return 0, err
	}

	return userNsInode, nil
}
