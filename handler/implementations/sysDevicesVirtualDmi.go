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
// /sys/devices/virtual/dmi handler
//
// Emulated resources:
//
// * /sys/devices/virtual/dmi
//
// In hardware platforms with reduced (or lacking) SMBIOS/DMI support (e.g., arm64),
// the "/sys/devices/virtual/dmi" path hierarchy is absent. In consequence, Sysbox
// must explictly expose the "dmi" directoy as this one contains critical system
// nodes utilized by certain applications.
//
// * /sys/devices/virtual/dmi/id
//
// Same as above. The "id" subdirectory must be emulated too as this contains
// SMBIOS data usually queried by DMI tools.
//

type SysDevicesVirtualDmi struct {
	domain.HandlerBase
}

var SysDevicesVirtualDmi_Handler = &SysDevicesVirtualDmi{
	domain.HandlerBase{
		Name:    "SysDevicesVirtualDmi",
		Path:    "/sys/devices/virtual/dmi",
		Enabled: true,
		EmuResourceMap: map[string]*domain.EmuResource{
			".": {
				Kind:    domain.DirEmuResource,
				Mode:    os.ModeDir | os.FileMode(uint32(0755)),
				Enabled: true,
			},
			"id": {
				Kind:    domain.DirEmuResource,
				Mode:    os.ModeDir | os.FileMode(uint32(0755)),
				Enabled: true,
			},
		},
	},
}

func (h *SysDevicesVirtualDmi) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	relpath, err := filepath.Rel(h.Path, n.Path())
	if err != nil {
		return nil, err
	}

	var resource = relpath

	// Users should not be allowed to alter any of the sysfs nodes being exposed. We
	// accomplish this by returning "nobody:nogroup" to the user during lookup() /
	// getattr() operations. This behavior is enforced by setting the handler's
	// SkipIdRemap value to 'true' to alert callers of the need to leave the returned
	// uid/gid as is (uid=0, gid=0).
	req.SkipIdRemap = true

	// Return an artificial fileInfo if looked-up element matches any of the
	// emulated components.
	if v, ok := h.EmuResourceMap[resource]; ok {

		if resource == "." {
			resource = "dmi"
		}

		info := &domain.FileInfo{
			Fname:    resource,
			Fmode:    v.Mode,
			FmodTime: time.Now(),
		}

		if v.Kind == domain.DirEmuResource {
			info.FisDir = true
		}

		return info, nil
	}

	return n.Stat()
}

func (h *SysDevicesVirtualDmi) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	logrus.Debugf("Executing Open() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	return nil
}

func (h *SysDevicesVirtualDmi) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Read() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	return 0, nil
}

func (h *SysDevicesVirtualDmi) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Write() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	return 0, nil
}

func (h *SysDevicesVirtualDmi) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	var (
		fileEntries        []os.FileInfo
		emulatedElemsAdded bool
	)

	logrus.Debugf("Executing ReadDirAll() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	// Obtain relative path to the node being readdir().
	relpath, err := filepath.Rel(h.Path, n.Path())
	if err != nil {
		return nil, err
	}

	// Create info entries for emulated components.
	for k, v := range h.EmuResourceMap {
		if k == "." {
			continue
		}

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

func (h *SysDevicesVirtualDmi) GetName() string {
	return h.Name
}

func (h *SysDevicesVirtualDmi) GetPath() string {
	return h.Path
}

func (h *SysDevicesVirtualDmi) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *SysDevicesVirtualDmi) GetEnabled() bool {
	return h.Enabled
}

func (h *SysDevicesVirtualDmi) SetEnabled(b bool) {
	h.Enabled = b
}

func (h *SysDevicesVirtualDmi) GetResourcesList() []string {

	var resources []string

	for resourceKey, resource := range h.EmuResourceMap {
		resource.Mutex.Lock()
		if !resource.Enabled {
			resource.Mutex.Unlock()
			continue
		}
		resource.Mutex.Unlock()

		// Resource name must be adjusted to account for the presence of the "dmi"
		// directory (i.e., ".") as one of the emulated resources.
		if resourceKey == "." {
			resources = append(resources, h.Path)
		} else {
			resources = append(resources, filepath.Join(h.GetPath(), resourceKey))
		}
	}

	return resources
}

func (h *SysDevicesVirtualDmi) GetResourceMutex(n domain.IOnodeIface) *sync.Mutex {

	// Resource name must be adjusted to account for the possibility of caller asking
	// for the "dmi" directory itself (i.e., "." resource).
	relpath, err := filepath.Rel(h.Path, n.Path())
	if err != nil {
		return nil
	}
	var node = relpath

	resource, ok := h.EmuResourceMap[node]
	if !ok {
		return nil
	}

	return &resource.Mutex
}

func (h *SysDevicesVirtualDmi) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
