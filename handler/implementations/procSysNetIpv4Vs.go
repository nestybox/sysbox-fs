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
// The procfs nodes managed in this handler will only be visible if the path
// they rely on (/proc/sys/net/ipv4/vs") is exposed within the system, which
// can only happen if the "ip_vs" kernel module is loaded.
//

//
// Note: this resource is already namespaced by the Linux kernel's net-ns. However the
// resource is hidden inside a non-init user-namespace. Thus, this handler's only purpose
// is to expose the resource inside a sys container. The same applies to all other resources
// under "/proc/sys/net/ipv4/vs/", though this handler only deals with "conntrack".
//
//
// /proc/sys/net/ipv4/vs/conn_reuse_mode handler
//
// Note: this resource is already namespaced by the Linux kernel's net-ns. However the
// resource is hidden inside a non-init user-namespace. Thus, this handler's only purpose
// is to expose the resource inside a sys container. The same applies to all other resources
// under "/proc/sys/net/ipv4/vs/", though this handler only deals with "conn_reuse_mode".
//
//
// /proc/sys/net/ipv4/vs/expire_nodest_conn handler
//
// Note: this resource is already namespaced by the Linux kernel's net-ns. However the
// resource is hidden inside a non-init user-namespace. Thus, this handler's only purpose
// is to expose the resource inside a sys container. The same applies to all other resources
// under "/proc/sys/net/ipv4/vs/", though this handler only deals with "expire_nodest_conn".
//
// /proc/sys/net/ipv4/vs/expire_quiescent_template handler
//
// Note: this resource is already namespaced by the Linux kernel's net-ns. However the
// resource is hidden inside a non-init user-namespace. Thus, this handler's only purpose
// is to expose the resource inside a sys container. The same applies to all other resources
// under "/proc/sys/net/ipv4/vs/", though this handler only deals with "expire_quiescent_template".
//

const (
	minConnReuseMode = 0
	maxConnReuseMode = 1
)

type ProcSysNetIpv4Vs struct {
	domain.HandlerBase
}

var ProcSysNetIpv4Vs_Handler = &ProcSysNetIpv4Vs{
	domain.HandlerBase{
		Name: "ProcSysNetIpv4Vs",
		Path: "/proc/sys/net/ipv4/vs",
		EmuResourceMap: map[string]domain.EmuResource{
			"conntrack":                 {Kind: domain.FileEmuResource, Mode: os.FileMode(uint32(0644))},
			"conn_reuse_mode":           {Kind: domain.FileEmuResource, Mode: os.FileMode(uint32(0644))},
			"expire_nodest_conn":        {Kind: domain.FileEmuResource, Mode: os.FileMode(uint32(0644))},
			"expire_quiescent_template": {Kind: domain.FileEmuResource, Mode: os.FileMode(uint32(0644))},
		},
		Type:      domain.NODE_SUBSTITUTION,
		Enabled:   true,
		Cacheable: true,
	},
}

func (h *ProcSysNetIpv4Vs) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method for Req ID=%#x on %v handler",
		req.ID, h.Name)

	var lookupNode = filepath.Base(n.Path())

	// Return an artificial fileInfo if looked-up element matches any of the
	// emulated components.
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

func (h *ProcSysNetIpv4Vs) Getattr(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (*syscall.Stat_t, error) {

	return nil, nil
}

func (h *ProcSysNetIpv4Vs) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	return nil
}

func (h *ProcSysNetIpv4Vs) Close(n domain.IOnodeIface) error {

	return nil
}

func (h *ProcSysNetIpv4Vs) Read(
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
	case "conntrack":
		return readFileInt(h, n, req)

	case "conn_reuse_mode":
		return readFileInt(h, n, req)

	case "expire_nodest_conn":
		return readFileInt(h, n, req)

	case "expire_quiescent_template":
		return readFileInt(h, n, req)
	}

	// Refer to generic handler if no node match is found above.
	procSysCommonHandler, ok := h.Service.FindHandler("/proc/sys/")
	if !ok {
		return 0, fmt.Errorf("No /proc/sys/ handler found")
	}

	return procSysCommonHandler.Read(n, req)
}

func (h *ProcSysNetIpv4Vs) Write(
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
	case "conntrack":
		return writeFileMaxInt(h, n, req, true)

	case "conn_reuse_mode":
		return writeFileInt(h, n, req, minConnReuseMode, maxConnReuseMode, false)

	case "expire_nodest_conn":
		return writeFileInt(h, n, req, MinInt, MaxInt, false)

	case "expire_quiescent_template":
		return writeFileInt(h, n, req, MinInt, MaxInt, false)
	}

	// Refer to generic handler if no node match is found above.
	procSysCommonHandler, ok := h.Service.FindHandler("/proc/sys/")
	if !ok {
		return 0, fmt.Errorf("No /proc/sys/ handler found")
	}

	return procSysCommonHandler.Write(n, req)
}

func (h *ProcSysNetIpv4Vs) ReadDirAll(
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

	// Iterate through map of virtual components.
	for k, _ := range h.EmuResourceMap {
		info = &domain.FileInfo{
			Fname:    k,
			FmodTime: time.Now(),
		}

		fileEntries = append(fileEntries, info)
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

func (h *ProcSysNetIpv4Vs) GetName() string {
	return h.Name
}

func (h *ProcSysNetIpv4Vs) GetPath() string {
	return h.Path
}

func (h *ProcSysNetIpv4Vs) GetEnabled() bool {
	return h.Enabled
}

func (h *ProcSysNetIpv4Vs) GetType() domain.HandlerType {
	return h.Type
}

func (h *ProcSysNetIpv4Vs) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *ProcSysNetIpv4Vs) GetResourceMap() map[string]domain.EmuResource {
	return h.EmuResourceMap
}

func (h *ProcSysNetIpv4Vs) GetResourceMutex(s string) *sync.Mutex {
	resource, ok := h.EmuResourceMap[s]
	if !ok {
		return nil
	}

	return &resource.Mutex
}

func (h *ProcSysNetIpv4Vs) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *ProcSysNetIpv4Vs) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
