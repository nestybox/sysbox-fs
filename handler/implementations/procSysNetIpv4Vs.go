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
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
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
		Name:    "ProcSysNetIpv4Vs",
		Path:    "/proc/sys/net/ipv4/vs",
		Enabled: true,
		EmuResourceMap: map[string]*domain.EmuResource{
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

	logrus.Debugf("Executing Lookup() for req-id: %#x, handler: %s, resource: %s",
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
	return h.Service.GetPassThroughHandler().Lookup(n, req)
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

	logrus.Debugf("Executing Read() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	// We are dealing with a single boolean element being read, so we can save
	// some cycles by returning right away if offset is any higher than zero.
	if req.Offset > 0 {
		return 0, io.EOF
	}

	switch resource {
	case "conntrack":
		return readCntrData(h, n, req)

	case "conn_reuse_mode":
		return readCntrData(h, n, req)

	case "expire_nodest_conn":
		return readCntrData(h, n, req)

	case "expire_quiescent_template":
		return readCntrData(h, n, req)
	}

	// Refer to generic handler if no node match is found above.
	return h.Service.GetPassThroughHandler().Read(n, req)
}

func (h *ProcSysNetIpv4Vs) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	var resource = n.Name()

	logrus.Debugf("Executing Write() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	switch resource {
	case "conntrack":
		return writeCntrData(h, n, req, writeMaxIntToFs)

	case "conn_reuse_mode":
		if !checkIntRange(req.Data, minConnReuseMode, maxConnReuseMode) {
			return 0, fuse.IOerror{Code: syscall.EINVAL}
		}
		return writeCntrData(h, n, req, nil)

	case "expire_nodest_conn":
		if !checkIntRange(req.Data, math.MinInt32, math.MaxInt32) {
			return 0, fuse.IOerror{Code: syscall.EINVAL}
		}
		return writeCntrData(h, n, req, nil)

	case "expire_quiescent_template":
		if !checkIntRange(req.Data, math.MinInt32, math.MaxInt32) {
			return 0, fuse.IOerror{Code: syscall.EINVAL}
		}
		return writeCntrData(h, n, req, nil)
	}

	// Refer to generic handler if no node match is found above.
	return h.Service.GetPassThroughHandler().Write(n, req)
}

func (h *ProcSysNetIpv4Vs) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	var resource = n.Name()

	logrus.Debugf("Executing ReadDirAll() for req-id: %#x, handler: %s, resource: %s",
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

	// Obtain the usual entries seen within container's namespaces and add them
	// to the emulated ones.
	usualEntries, err := h.Service.GetPassThroughHandler().ReadDirAll(n, req)
	if err == nil {
		fileEntries = append(fileEntries, usualEntries...)
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

func (h *ProcSysNetIpv4Vs) GetEnabled() bool {
	return h.Enabled
}

func (h *ProcSysNetIpv4Vs) SetEnabled(b bool) {
	h.Enabled = b
}

func (h *ProcSysNetIpv4Vs) GetResourcesList() []string {

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
func (h *ProcSysNetIpv4Vs) GetResourceMutex(n domain.IOnodeIface) *sync.Mutex {
	resource, ok := h.EmuResourceMap[n.Name()]
	if !ok {
		return nil
	}

	return &resource.Mutex
}

func (h *ProcSysNetIpv4Vs) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
