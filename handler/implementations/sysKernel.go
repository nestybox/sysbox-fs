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
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
)

//
// /sys/kernel handler
//
// The following dirs are emulated within /sys/kernel directory to ensure that
// they are exposed within sys containers regardless of the system's kernel
// configuration in place (i.e., they are absent in systems where configfs,
// debugfs and tracefs kernel modules are dissabled). Moreover, even if these
// modules were to be loaded, their associated sysfs nodes would still appear as
// 'nobody:nogroup' as they are being accessed by process hosted within a
// non-init user-ns. By virtue of emulating them, we expose them with proper
// permissions.
//
// Emulated resources:
//
// * /sys/kernel/config
// * /sys/kernel/debug
// * /sys/kernel/tracing
//
// Finally, notice that unlike the procSys handler, we don't rely on the
// "passthrough" handler to access the "/sys/kernel" file hierarchy through
// nsenter() into the container's namespaces. Rather, we are accessing the files
// directly through the host's sysfs. This approach is feasible due to the
// global (i.e., system-wide) nature of /sys/kernel.
//

type SysKernel struct {
	domain.HandlerBase
}

var SysKernel_Handler = &SysKernel{
	domain.HandlerBase{
		Name:    "SysKernel",
		Path:    "/sys/kernel",
		Enabled: true,

		// Emulated components under /sys/kernel
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

	// Non-emulated files/dirs under /sys/kernel should show up without
	// permissions inside the sysbox container.
	req.SkipIdRemap = true

	return n.Stat()
}

func (h *SysKernel) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	var resource = n.Name()

	logrus.Debugf("Executing Open() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	// All emulated resources are currently dummy / empty
	for emu, _ := range h.EmuResourceMap {
		if emu == resource {
			return nil
		}
	}

	return n.Open()
}

func (h *SysKernel) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	var resource = n.Name()

	logrus.Debugf("Executing Read() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	if req.Offset != 0 {
		return 0, nil
	}

	// All emulated resources are currently dummy / empty
	for emu, _ := range h.EmuResourceMap {
		if emu == resource {
			return 0, nil
		}
	}

	return readHostFs(h, n, req.Offset, &req.Data)
}

func (h *SysKernel) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

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

	// Create info entries for emulated components under /sys/kernel
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
