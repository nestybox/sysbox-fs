//
// Copyright 2019-2022 Nestybox, Inc.
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
)

//
// /sys/kernel handler
//
// The following sysfs nodes are emulated to ensure that they are exposed within sys
// containers regardless of the system's kernel configuration in place (i.e., they
// are absent in systems where configfs, debugfs and tracefs kernel modules are
// dissabled). Moreover, even if these modules were to be loaded, their associated
// sysfs nodes would still appear as 'nobody:nogroup' as they are being accessed by
// process hosted within a non-init user-ns. Having said that, be aware that, as of
// today, the emulation provided as part of this handler is quite shallow: we are
// simply exposing these nodes with the proper permissions, no actual content is
// displayed within these folders for security / isolation purposes.
//
// Emulated resources:
//
// * /sys/kernel/config
//
// * /sys/kernel/debug
//
// * /sys/kernel/tracing
//
// Finally, notice that in this case we are not relying on the "passthrough" handler
// to access the "/sys/kernel" file hierarchy through nsenter() into the container's
// namespaces. Rather, we are accessing the files directly through the host's sysfs.
// This approach is feasible due to the global / system-wide nature of /sys/kernel.
//

type SysKernel struct {
	domain.HandlerBase
}

var SysKernel_Handler = &SysKernel{
	domain.HandlerBase{
		Name:    "SysKernel",
		Path:    "/sys/kernel/",
		Enabled: true,
		EmuResourceMap: map[string]*domain.EmuResource{
			"config": {
				Kind:    domain.DirEmuResource,
				Mode:    os.ModeDir | os.FileMode(uint32(0755)),
				Enabled: true,
			},
			"debug": {
				Kind:    domain.DirEmuResource,
				Mode:    os.ModeDir | os.FileMode(uint32(0700)),
				Enabled: true,
			},
			"tracing": {
				Kind:    domain.DirEmuResource,
				Mode:    os.ModeDir | os.FileMode(uint32(0700)),
				Enabled: true,
			},
		},
	},
}

func (h *SysKernel) Lookup(
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

	info, err := n.Stat()
	if err != nil {
		return nil, err
	}

	// Users should not be allowed to alter any of the sysfs nodes being exposed. To
	// enforce this, we hard-code the node's uid/gid to a value beyond the containers
	// uid/gid ranges so that they are displayed as "nobody:nogroup" within the sys
	// containers (yes, this value will be always considered out-of-range, even if
	// '--subid-range-size' knob is in place).
	info.Sys().(*syscall.Stat_t).Uid = domain.MaxUid
	info.Sys().(*syscall.Stat_t).Gid = domain.MaxGid

	return info, nil
}

func (h *SysKernel) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	var resource = n.Name()

	logrus.Debugf("Executing Open() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	switch resource {

	case "config":
		return nil

	case "debug":
		return nil

	case "tracing":
		return nil
	}

	return n.Open()
}

func (h *SysKernel) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	var resource = n.Name()

	logrus.Debugf("Executing Read() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	if req.Offset != 0 {
		return 0, nil
	}

	switch resource {

	case "config":
		return 0, nil

	case "debug":
		return 0, nil

	case "tracing":
		return 0, nil
	}

	return readHostFs(h, n, req.Offset, &req.Data)
}

func (h *SysKernel) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Write() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	// No write() access is allowed within "/sys/kernel" file hierarchy.
	return 0, nil
}

func (h *SysKernel) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	var resource = n.Name()

	logrus.Debugf("Executing ReadDirAll() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	var fileEntries []os.FileInfo

	// Obtain relative path to the node being readdir().
	relpath, err := filepath.Rel(h.Path, n.Path())
	if err != nil {
		return nil, err
	}

	var emulatedElemsAdded bool

	// Create info entries for emulated components.
	for k, v := range h.EmuResourceMap {
		if relpath != filepath.Dir(k) {
			continue
		}

		info := &domain.FileInfo{
			Fname:    k,
			Fmode:    v.Mode,
			FmodTime: time.Now(),
		}

		if v.Kind == domain.DirEmuResource {
			info.FisDir = true
		}

		fileEntries = append(fileEntries, info)

		emulatedElemsAdded = true
	}

	// Obtain the usual node entries.
	usualEntries, err := n.ReadDirAll()
	if err == nil {
		fileEntries = append(fileEntries, usualEntries...)
	}

	// Uniquify entries to return.
	if emulatedElemsAdded {
		fileEntries = domain.FileInfoSliceUniquify(fileEntries)
	}

	return fileEntries, nil
}

func (h *SysKernel) GetName() string {
	return h.Name
}

func (h *SysKernel) GetPath() string {
	return h.Path
}

func (h *SysKernel) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *SysKernel) GetEnabled() bool {
	return h.Enabled
}

func (h *SysKernel) SetEnabled(b bool) {
	h.Enabled = b
}

func (h *SysKernel) GetResourcesList() []string {

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

func (h *SysKernel) GetResourceMutex(n domain.IOnodeIface) *sync.Mutex {
	resource, ok := h.EmuResourceMap[n.Name()]
	if !ok {
		return nil
	}

	return &resource.Mutex
}

func (h *SysKernel) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
