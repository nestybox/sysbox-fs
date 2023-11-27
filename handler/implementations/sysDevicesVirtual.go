//
// Copyright 2019-2023 Nestybox, Inc.
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
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
)

//
// /sys/devices/virtual handler
//
// * /sys/devices/virtual/dmi
//
// In hardware platforms with reduced (or lacking) SMBIOS/DMI support (e.g., arm64),
// the "/sys/devices/virtual/dmi" path hierarchy is absent. In consequence, Sysbox
// must explicitly expose the "dmi" directory as this one contains critical system
// nodes utilized by certain applications.
//

type SysDevicesVirtual struct {
	domain.HandlerBase
	passthruNodes map[string]bool
}

var SysDevicesVirtual_Handler = &SysDevicesVirtual{
	domain.HandlerBase{
		Name:    "SysDevicesVirtual",
		Path:    "/sys/devices/virtual",
		Enabled: true,
		EmuResourceMap: map[string]*domain.EmuResource{
			".": {
				Kind:    domain.DirEmuResource,
				Mode:    os.ModeDir | os.FileMode(uint32(0755)),
				Enabled: true,
			},
			"dmi": {
				Kind:    domain.DirEmuResource,
				Mode:    os.ModeDir | os.FileMode(uint32(0755)),
				Enabled: true,
			},
		},
	},
	map[string]bool{
		"net": true,
	},
}

func (h *SysDevicesVirtual) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	// Users should not be allowed to alter any of the sysfs nodes being exposed. We
	// accomplish this by returning "nobody:nogroup" to the user during lookup() /
	// getattr() operations. This behavior is enforced by setting the handler's
	// SkipIdRemap value to 'true' to alert callers of the need to leave the returned
	// uid/gid as is (uid=0, gid=0).
	req.SkipIdRemap = true

	// Return an artificial fileInfo if looked-up element matches any of the
	// emulated components.
	relpath, err := filepath.Rel(h.Path, n.Path())
	if err != nil {
		return nil, err
	}

	var resource = relpath

	if v, ok := h.EmuResourceMap[resource]; ok {
		if resource == "." {
			resource = "virtual"
		}

		info := &domain.FileInfo{
			Fname:    resource,
			Fmode:    v.Mode,
			Fsize:    v.Size,
			FmodTime: time.Now(),
		}

		if v.Kind == domain.DirEmuResource {
			info.FisDir = true
		}

		return info, nil
	}

	// For non emulated resources under /sys/devices/virtual, we should
	// ideally request the passthrough handler to always perform the lookup;
	// however this slows down the lookup and causes sysbox containers with
	// systemd inside to fail in hosts with kernel < 5.19 (i.e., systemd takes
	// too long to boot because for some reason it's doing lots of lookups of
	// /sys/virtual/devices/block/loopX devices, causing it to timeout). Instead
	// we do the lookup at host level, except for resources under /sys/devices/virtual
	// for which we know we must enter the container namespaces.
	for node, _ := range h.passthruNodes {
		if node == resource || strings.HasPrefix(resource, node+"/") {
			return h.Service.GetPassThroughHandler().Lookup(n, req)
		}
	}

	return n.Lstat()
}

func (h *SysDevicesVirtual) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	logrus.Debugf("Executing Open() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	return nil
}

func (h *SysDevicesVirtual) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Read() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	relpath, err := filepath.Rel(h.Path, n.Path())
	if err != nil {
		return 0, err
	}

	var resource = relpath

	for node, _ := range h.passthruNodes {
		if node == resource || strings.HasPrefix(resource, node+"/") {
			return h.Service.GetPassThroughHandler().Read(n, req)
		}
	}

	return 0, nil
}

func (h *SysDevicesVirtual) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Write() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	relpath, err := filepath.Rel(h.Path, n.Path())
	if err != nil {
		return 0, err
	}

	var resource = relpath

	for node, _ := range h.passthruNodes {
		if node == resource || strings.HasPrefix(resource, node+"/") {
			return h.Service.GetPassThroughHandler().Write(n, req)
		}
	}

	return 0, nil
}

func (h *SysDevicesVirtual) ReadDirAll(
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

	var resource = relpath

	// Invoke the passthrough handler for the corresponding resources (e.g., /sys/devices/virtual/net).
	// We return here since we are looking for the host's view of these resources -- i.e., we don't
	// want to include emulated resources here (emuResourceMap).
	for node, _ := range h.passthruNodes {
		if node == resource || strings.HasPrefix(resource, node+"/") {
			return h.Service.GetPassThroughHandler().ReadDirAll(n, req)
		}
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
	if err != nil {
		return nil, err
	}

	fileEntries = append(fileEntries, usualEntries...)

	if emulatedElemsAdded {
		fileEntries = domain.FileInfoSliceUniquify(fileEntries)
	}

	return fileEntries, nil
}

func (h *SysDevicesVirtual) ReadLink(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (string, error) {

	logrus.Debugf("Executing ReadLink() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	// Obtain relative path to the node being readlink().
	relpath, err := filepath.Rel(h.Path, n.Path())
	if err != nil {
		return "", err
	}

	var resource = relpath

	// Invoke the passthrough handler for the passthrough resources.
	for node, _ := range h.passthruNodes {
		if node == resource || strings.HasPrefix(resource, node+"/") {
			return h.Service.GetPassThroughHandler().ReadLink(n, req)
		}
	}

	return n.ReadLink()
}

func (h *SysDevicesVirtual) GetName() string {
	return h.Name
}

func (h *SysDevicesVirtual) GetPath() string {
	return h.Path
}

func (h *SysDevicesVirtual) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *SysDevicesVirtual) GetEnabled() bool {
	return h.Enabled
}

func (h *SysDevicesVirtual) SetEnabled(b bool) {
	h.Enabled = b
}

func (h *SysDevicesVirtual) GetResourcesList() []string {

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

func (h *SysDevicesVirtual) GetResourceMutex(n domain.IOnodeIface) *sync.Mutex {
	resource, ok := h.EmuResourceMap[n.Name()]
	if !ok {
		return nil
	}

	return &resource.Mutex
}

func (h *SysDevicesVirtual) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
