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
	"fmt"
	"os"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/handler/implementations"

	iradix "github.com/hashicorp/go-immutable-radix"
)

//
// Slice of sysbox-fs' default handlers and the respective paths where they
// apply. Notice that the path associated to the pass-through handler is
// symbolic as this one can be invoked from within any of the other handlers,
// regardless of the FS location where they operate.
//
var DefaultHandlers = []domain.HandlerIface{
	implementations.PassThrough_Handler,                    // *
	implementations.Root_Handler,                           // /
	implementations.Proc_Handler,                           // /proc
	implementations.ProcSys_Handler,                        // /proc/sys/
	implementations.ProcSysFs_Handler,                      // /proc/sys/fs
	implementations.ProcSysKernel_Handler,                  // /proc/sys/kernel
	implementations.ProcSysKernelYama_Handler,              // /proc/sys/kernel/yama
	implementations.ProcSysNetCore_Handler,                 // /proc/sys/net/core
	implementations.ProcSysNetIpv4_Handler,                 // /proc/sys/net/ipv4
	implementations.ProcSysNetIpv4Vs_Handler,               // /proc/sys/net/ipv4/vs
	implementations.ProcSysNetIpv4Neigh_Handler,            // /proc/sys/net/ipv4/neigh
	implementations.ProcSysNetNetfilter_Handler,            // /proc/sys/net/netfilter
	implementations.ProcSysNetUnix_Handler,                 // /proc/sys/net/unix
	implementations.ProcSysVm_Handler,                      // /proc/sys/vm
	implementations.Sys_Handler,                            // /sys
	implementations.SysKernel_Handler,                      // /sys/kernel/
	implementations.SysDevicesVirtualDmiId_Handler,         // /sys/devices/virtual/dmi/id
	implementations.SysModuleNfconntrackParameters_Handler, // /sys/module/nf_conntrack/parameters
}

type handlerService struct {
	sync.RWMutex

	// Radix-tree indexed by node FS path. Tree serves as an ordered DB where to
	// keep track of the association between the FS nodes being emulated, and
	// their matching handler object.
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

	// Passthrough handler.
	passThroughHandler domain.HandlerIface

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

	// Register all handlers declared and their associated resources.
	for _, h := range hdlrs {
		hs.RegisterHandler(h)
	}

	// Set pointer to passthrough handler.
	hs.passThroughHandler = implementations.PassThrough_Handler

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

	var h domain.HandlerIface

	// Iterate the handler's radix-tree looking for the handler that better
	// match the fs node being searched.
	//
	// Notice that this approach could potentially lead to overlapping scenarios
	// if we were to have handlers such as "/proc/update" and "/proc/update_1",
	// but there's no such a case today. If we ever need to address this point,
	// we would simply extend this handler-lookup logic by placing it in a "for"
	// loop and by comparing the "base" components of the overlapping elements.
	_, node, ok := hs.handlerTree.Root().LongestPrefix([]byte(i.Path()))
	if !ok {
		return nil, false
	}

	h = node.(domain.HandlerIface)

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

func (hs *handlerService) EnableHandler(path string) error {
	hs.Lock()
	defer hs.Unlock()

	h, ok := hs.FindHandler(path)
	if !ok {
		return fmt.Errorf("handler %s not found in handlerDB", path)
	}

	h.SetEnabled(true)

	return nil
}

func (hs *handlerService) DisableHandler(path string) error {
	hs.Lock()
	defer hs.Unlock()

	h, ok := hs.FindHandler(path)
	if !ok {
		return fmt.Errorf("handler %s not found in handlerDB", path)
	}

	h.SetEnabled(false)

	return nil
}

func (hs *handlerService) HandlersResourcesList() []string {

	var resourcesList []string

	// Technically not needed as this method is only expected to be called
	// during sysbox-fs initialization (handlers are not in service at that
	// point), but just in case utilization changes overtime.
	hs.RLock()
	defer hs.RUnlock()

	// Iterate through the handlerDB to extract the list of resources being
	// emulated.
	hs.handlerTree.Root().Walk(func(key []byte, val interface{}) bool {

		h := val.(domain.HandlerIface)
		if !h.GetEnabled() {
			return true
		}

		list := h.GetResourcesList()
		resourcesList = append(resourcesList, list...)

		return false
	})

	return resourcesList
}

func (hs *handlerService) GetPassThroughHandler() domain.HandlerIface {
	return hs.passThroughHandler
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
