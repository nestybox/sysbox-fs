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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
)

//
// /proc/sys/net/core handler
//
// Emulated resources:
//
// * /proc/sys/net/core/default_qdisc
//
// Documentation: The default queuing discipline to use for network devices.
// This allows overriding the default of pfifo_fast with an alternative. Since
// the default queuing discipline is created without additional parameters so
// is best suited to queuing disciplines that work well without configuration
// like stochastic fair queue (sfq), CoDel (codel) or fair queue CoDel
// (fq_codel). Don’t use queuing disciplines like Hierarchical Token Bucket or
// Deficit Round Robin which require setting up classes and bandwidths. Note
// that physical multiqueue interfaces still use mq as root qdisc, which in
// turn uses this default for its leaves. Virtual devices (like e.g. lo or
// veth) ignore this setting and instead default to noqueue. Default:
// pfifo_fast.
//
// Supported schedulers (https://github.com/torvalds/linux/blob/master/net/sched/Kconfig#L478):
//
// 	- "pfifo_fast"
//	- "fq"
//	- "fq_codel"
//	- "sfq"
//	- "pfifo_fast"
//
// As this is a system-wide attribute with mutually-exclusive values, changes
// will be only made superficially (at sys-container level). IOW, the host FS
// value will be left untouched.
//
// * /proc/sys/net/core/somaxconn
//
// Description: Limit of socket listen() backlog, known in userspace as SOMAXCONN.
// Somaxconn refers to the maximum number of clients that the server can accept
// to process data, that is, to complete the connection limit. Defaults to 128.
//
type ProcSysNetCore struct {
	domain.HandlerBase
}

var ProcSysNetCore_Handler = &ProcSysNetCore{
	domain.HandlerBase{
		Name:    "ProcSysNetCore",
		Path:    "/proc/sys/net/core",
		Enabled: true,
		EmuResourceMap: map[string]*domain.EmuResource{
			"default_qdisc": {
				Kind:    domain.FileEmuResource,
				Mode:    os.FileMode(uint32(0644)),
				Enabled: true,
			},
			"somaxconn": {
				Kind:    domain.FileEmuResource,
				Mode:    os.FileMode(uint32(0644)),
				Enabled: true,
			},
		},
	},
}

func (h *ProcSysNetCore) Lookup(
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

func (h *ProcSysNetCore) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	return nil
}

func (h *ProcSysNetCore) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	var resource = n.Name()

	logrus.Debugf("Executing Read() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	switch resource {
	case "default_qdisc":
		return readCntrData(h, n, req)

	case "somaxconn":
		return readCntrData(h, n, req)
	}

	// Refer to generic handler if no node match is found above.
	return h.Service.GetPassThroughHandler().Read(n, req)
}

func (h *ProcSysNetCore) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	var resource = n.Name()

	logrus.Debugf("Executing Write() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	switch resource {
	case "default_qdisc":
		return h.writeDefaultQdisc(n, req)

	case "somaxconn":
		return writeCntrData(h, n, req, writeMaxIntToFs)
	}

	// Refer to generic handler if no node match is found above.
	return h.Service.GetPassThroughHandler().Write(n, req)
}

func (h *ProcSysNetCore) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	var resource = n.Name()

	logrus.Debugf("Executing ReadDirAll() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	var fileEntries []os.FileInfo

	// Iterate through map of emulated components.
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

func (h *ProcSysNetCore) GetName() string {
	return h.Name
}

func (h *ProcSysNetCore) GetPath() string {
	return h.Path
}

func (h *ProcSysNetCore) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *ProcSysNetCore) GetEnabled() bool {
	return h.Enabled
}

func (h *ProcSysNetCore) SetEnabled(b bool) {
	h.Enabled = b
}

func (h *ProcSysNetCore) GetResourcesList() []string {

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
func (h *ProcSysNetCore) GetResourceMutex(n domain.IOnodeIface) *sync.Mutex {
	resource, ok := h.EmuResourceMap[n.Name()]
	if !ok {
		return nil
	}

	return &resource.Mutex
}

func (h *ProcSysNetCore) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}

func (h *ProcSysNetCore) writeDefaultQdisc(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	newVal := strings.TrimSpace(string(req.Data))

	// Only supported values must be accepted.
	switch newVal {
	case "fq":
	case "fq_codel":
	case "sfq":
	case "pfifo_fast":
	default:
		return 0, fuse.IOerror{Code: syscall.EINVAL}
	}

	return writeCntrData(h, n, req, writeToFs)
}
