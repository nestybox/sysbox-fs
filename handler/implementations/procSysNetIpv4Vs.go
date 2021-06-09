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
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
)

//
// /proc/sys/net/ipv4/vs handler
//
// Note: The procfs nodes managed by this handler will only be visible if the
// path they are part of (/proc/sys/net/ipv4/vs") is exposed within the system,
// which can only happen if the "ip_vs" kernel module is loaded.
//
// Note: the resources handled by this handler are already namespaced by the
// Linux kernel's net-ns. However, these resources are hidden inside non-init
// user-namespace. Thus, this handler's only purpose is to expose these
// resources inside a sys container.
//
// Emulated resources:
//
// * /proc/sys/net/ipv4/vs/conn_reuse_mode handler
//
// * /proc/sys/net/ipv4/vs/expire_nodest_conn handler
//
// * /proc/sys/net/ipv4/vs/expire_quiescent_template handler
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
			"conntrack": {
				Kind:    domain.FileEmuResource,
				Mode:    os.FileMode(uint32(0644)),
				Enabled: true,
			},
			"conn_reuse_mode": {
				Kind:    domain.FileEmuResource,
				Mode:    os.FileMode(uint32(0644)),
				Enabled: true,
			},
			"expire_nodest_conn": {
				Kind:    domain.FileEmuResource,
				Mode:    os.FileMode(uint32(0644)),
				Enabled: true,
			},
			"expire_quiescent_template": {
				Kind:    domain.FileEmuResource,
				Mode:    os.FileMode(uint32(0644)),
				Enabled: true,
			},
		},
	},
}

func (h *ProcSysNetIpv4Vs) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	var resource = n.Name()

	logrus.Debugf("Executing Lookup() for Req ID=%#x, %v handler, resource %s",
		req.ID, h.Name, resource)

	// Return an artificial fileInfo if looked-up element matches any of the
	// emulated components.
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
	procSysCommonHandler, ok := h.Service.FindHandler("/proc/sys/")
	if !ok {
		return nil, fmt.Errorf("No /proc/sys/ handler found")
	}

	return procSysCommonHandler.Lookup(n, req)
}

func (h *ProcSysNetIpv4Vs) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	return nil
}

func (h *ProcSysNetIpv4Vs) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	var resource = n.Name()

	logrus.Debugf("Executing Read() for Req ID=%#x, %v handler, resource %s",
		req.ID, h.Name, resource)

	// We are dealing with a single boolean element being read, so we can save
	// some cycles by returning right away if offset is any higher than zero.
	if req.Offset > 0 {
		return 0, io.EOF
	}

	switch resource {
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

	var resource = n.Name()

	logrus.Debugf("Executing Write() for Req ID=%#x, %v handler, resource %s",
		req.ID, h.Name, resource)

	switch resource {
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

	var resource = n.Name()

	logrus.Debugf("Executing ReadDirAll() for Req ID=%#x, %v handler, resource %s",
		req.ID, h.Name, resource)

	var fileEntries []os.FileInfo

	// Iterate through map of virtual components.
	for k, _ := range h.EmuResourceMap {
		info := &domain.FileInfo{
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

func (h *ProcSysNetIpv4Vs) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
