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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
)

//
// /proc/sys/net/netfilter handlers
//
// Emulated nodes:
//
// * /proc/sys/net/netfilter/nf_conntrack_tcp_be_liberal
//
// Documentation: https://www.kernel.org/doc/Documentation/networking/nf_conntrack-sysctl.txt
//
// nf_conntrack_tcp_be_liberal - BOOLEAN
// 	0 - disabled (default)
// 	not 0 - enabled
//
// 	Be conservative in what you do, be liberal in what you accept from others.
// 	If it's non-zero, we mark only out of window RST segments as INVALID.
//
// Taking into account that kernel's netfilter can either operate in one mode or
// the other, we opt for letting the liberal mode prevail if set within any sys-container.
//

const (
	tcpLiberalOff = 0
	tcpLiberalOn  = 1
)

type ProcSysNetNetfilter struct {
	domain.HandlerBase
}

var ProcSysNetNetfilter_Handler = &ProcSysNetNetfilter{
	domain.HandlerBase{
		Name: "ProcSysNetNetfilter",
		Path: "/proc/sys/net/netfilter",
		EmuResourceMap: map[string]domain.EmuResource{
			"nf_conntrack_max":                     {Kind: domain.FileEmuResource, Mode: os.FileMode(uint32(0644))},
			"nf_conntrack_generic_timeout":         {Kind: domain.FileEmuResource, Mode: os.FileMode(uint32(0644))},
			"nf_conntrack_tcp_be_liberal":          {Kind: domain.FileEmuResource, Mode: os.FileMode(uint32(0644))},
			"nf_conntrack_tcp_timeout_established": {Kind: domain.FileEmuResource, Mode: os.FileMode(uint32(0644))},
			"nf_conntrack_tcp_timeout_close_wait":  {Kind: domain.FileEmuResource, Mode: os.FileMode(uint32(0644))},
		},
		Type:      domain.NODE_SUBSTITUTION,
		Enabled:   true,
		Cacheable: true,
	},
}

func (h *ProcSysNetNetfilter) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method for Req ID=%#x on %v handler",
		req.ID, h.Name)

	var lookupNode = filepath.Base(n.Path())

	// Return an artificial fileInfo if looked-up element matches any of the
	// virtual-components.
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

func (h *ProcSysNetNetfilter) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	logrus.Debugf("Executing %v Open() method\n", h.Name)

	return nil
}

func (h *ProcSysNetNetfilter) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing %v Read() method", h.Name)

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
	case "nf_conntrack_max":
		return readFileInt(h, n, req)

	case "nf_conntrack_generic_timeout":
		return readFileInt(h, n, req)

	case "nf_conntrack_tcp_be_liberal":

	case "nf_conntrack_tcp_timeout_established":
		return readFileInt(h, n, req)

	case "nf_conntrack_tcp_timeout_close_wait":
		return readFileInt(h, n, req)
	}

	// Refer to generic handler if no node match is found above.
	procSysCommonHandler, ok := h.Service.FindHandler("/proc/sys/")
	if !ok {
		return 0, fmt.Errorf("No /proc/sys/ handler found")
	}

	return procSysCommonHandler.Read(n, req)
}

func (h *ProcSysNetNetfilter) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing %v Write() method", h.Name)

	name := n.Name()
	cntr := req.Container

	// Ensure operation is generated from within a registered sys container.
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return 0, errors.New("Container not found")
	}

	switch name {
	case "nf_conntrack_max":
		return writeFileMaxInt(h, n, req, true)

	case "nf_conntrack_generic_timeout":
		return writeFileMaxInt(h, n, req, true)

	case "nf_conntrack_tcp_be_liberal":
		return h.writeTcpLiberal(n, req)

	case "nf_conntrack_tcp_timeout_established":
		return writeFileMaxInt(h, n, req, true)

	case "nf_conntrack_tcp_timeout_close_wait":
		return writeFileMaxInt(h, n, req, true)
	}

	// Refer to generic handler if no node match is found above.
	procSysCommonHandler, ok := h.Service.FindHandler("/proc/sys/")
	if !ok {
		return 0, fmt.Errorf("No /proc/sys/ handler found")
	}

	return procSysCommonHandler.Write(n, req)
}

func (h *ProcSysNetNetfilter) ReadDirAll(
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

	var (
		info        *domain.FileInfo
		fileEntries []os.FileInfo
	)

	// Obtain relative path to the element being read.
	relpath, err := filepath.Rel(h.Path, n.Path())
	if err != nil {
		return nil, err
	}

	// Iterate through map of emulated components.
	for k, _ := range h.EmuResourceMap {

		if relpath == filepath.Dir(k) {
			info = &domain.FileInfo{
				Fname:    filepath.Base(k),
				Fmode:    os.FileMode(uint32(0644)),
				FmodTime: time.Now(),
			}

			fileEntries = append(fileEntries, info)
		}
	}

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

func (h *ProcSysNetNetfilter) GetName() string {
	return h.Name
}

func (h *ProcSysNetNetfilter) GetPath() string {
	return h.Path
}

func (h *ProcSysNetNetfilter) GetEnabled() bool {
	return h.Enabled
}

func (h *ProcSysNetNetfilter) GetType() domain.HandlerType {
	return h.Type
}

func (h *ProcSysNetNetfilter) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *ProcSysNetNetfilter) GetResourceMap() map[string]domain.EmuResource {
	return h.EmuResourceMap
}

func (h *ProcSysNetNetfilter) GetResourceMutex(s string) *sync.Mutex {
	resource, ok := h.EmuResourceMap[s]
	if !ok {
		return nil
	}

	return &resource.Mutex
}

func (h *ProcSysNetNetfilter) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *ProcSysNetNetfilter) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}

func (h *ProcSysNetNetfilter) writeTcpLiberal(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	name := n.Name()
	path := n.Path()
	cntr := req.Container

	// Ensure operation is generated from within a registered sys container.
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return 0, errors.New("Container not found")
	}

	newVal := strings.TrimSpace(string(req.Data))
	newValInt, err := strconv.Atoi(newVal)
	if err != nil {
		logrus.Errorf("Unexpected error: %v", err)
		return 0, err
	}

	if newValInt != tcpLiberalOff && newValInt != tcpLiberalOn {
		return 0, fuse.IOerror{Code: syscall.EINVAL}
	}

	cntr.Lock()
	defer cntr.Unlock()

	// Check if this resource has been initialized for this container. If not,
	// push it down to the kernel if, and only if, the new value is not equal
	// to tcpLiberalOff (0), as we want to kernel's tcpLiberalOn mode to
	// prevail.
	curVal, ok := cntr.Data(path, name)
	if !ok {
		if newValInt != tcpLiberalOff {
			if err := pushFileInt(h, n, cntr, newValInt); err != nil {
				return 0, err
			}
		}

		cntr.SetData(path, name, newVal)
		return len(req.Data), nil
	}

	curValInt, err := strconv.Atoi(curVal)
	if err != nil {
		logrus.Errorf("Unexpected error: %v", err)
		return 0, err
	}

	// If the new value is 0 or the same as the current value, then let's update
	// this new value into the container struct but not push it down to the
	// kernel.
	if newValInt == tcpLiberalOff || newValInt == curValInt {
		cntr.SetData(path, name, newVal)
		return len(req.Data), nil
	}

	// Push new value to the kernel.
	if err := pushFileInt(h, n, cntr, newValInt); err != nil {
		return 0, io.EOF
	}

	// Writing the new value into container-state struct.
	cntr.SetData(path, name, newVal)

	return len(req.Data), nil
}
