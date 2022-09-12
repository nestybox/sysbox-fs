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
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
	"github.com/nestybox/sysbox-libs/formatter"
)

//
// /sys/devices/virtual/dmi/id handler
//
// Emulated resources:
//
// * /sys/devices/virtual/dmi/id
//
// In hardware platforms with reduced (or lacking) SMBIOS/DMI support (e.g., arm64),
// the "/sys/devices/virtual/dmi/id" path hierarchy is absent. In consequence, Sysbox
// must explictly expose the "dmi" directoy as this one contains critical system
// nodes utilized by certain applications (see below).
//
// * /sys/devices/virtual/dmi/id/product_uuid
//
// The main purpose here is to allow each sys container to have a unique and
// stable UUID, to satisfy applications that rely on this value for their
// operation (e.g., Kubernetes, Weave CNI, Calico, etc). Notice that this is
// not an option in the regular (oci) runc, where all containers within a
// host/vm share the same UUID value.
//
// A host UUID is typically extracted from the 'product_uuid' sysfs node, and
// its value is represented by 36 characters with the following layout:
//
// $ cat /sys/class/dmi/id/product_uuid
// e617c421-0026-4941-9e95-56a1ab1f4cb3
//
// As we want to provide a unique and stable UUID for each container, we will
// expose an artificial 'product_uuid' file through this handler. The UUID
// value that will be displayed within each container's 'product_uuid' file
// will follow these simple guidelines:
//
// * The first 24 characters will continue to match those seen by the hosts (its
//   own UUID).
// * The last 12 characters will be extracted from the container ID field.
//
// In scenarios where no UUID is available for a given host (e.g., vm launched
// without qemu's --uuid parameter), no reference 'product_uuid' file will be
// found at the host level, so in this case we will set the first 24 characters
// of each container's UUID to zero.
//
// Example:
//
// e617c421-0026-4941-9e95-<sys-cntr-id-01>
// e617c421-0026-4941-9e95-<sys-cntr-id-02>
//
// 00000000-0000-0000-0000-<sys-cntr-id-03> // no 'product_uuid' found
//

// UUID constants as per rfc/4122
const (
	// Time + Version fields length
	timeFieldLen = 24

	// Node field length
	nodeFieldLen = 12
)

type SysDevicesVirtualDmiId struct {
	domain.HandlerBase
}

var SysDevicesVirtualDmiId_Handler = &SysDevicesVirtualDmiId{
	domain.HandlerBase{
		Name:    "SysDevicesVirtualDmiId",
		Path:    "/sys/devices/virtual/dmi/id",
		Enabled: true,
		EmuResourceMap: map[string]*domain.EmuResource{
			".": {
				Kind:    domain.DirEmuResource,
				Mode:    os.ModeDir | os.FileMode(uint32(0755)),
				Enabled: true,
			},
			"product_uuid": {
				Kind:    domain.FileEmuResource,
				Mode:    os.FileMode(uint32(0400)),
				Size:    4096,
				Enabled: true,
			},
		},
	},
}

func (h *SysDevicesVirtualDmiId) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	relpath, err := filepath.Rel(h.Path, n.Path())
	if err != nil {
		return nil, err
	}

	var resource = relpath

	// Return an artificial fileInfo if looked-up element matches any of the
	// emulated components.
	if v, ok := h.EmuResourceMap[resource]; ok {

		if resource == "." {
			resource = "id"
			// Skip uid/gid remaps for 'id' folder node.
			req.SkipIdRemap = true
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

	// Skip uid/gid remaps for all other (non-emulated) resources.
	req.SkipIdRemap = true

	return n.Stat()
}

func (h *SysDevicesVirtualDmiId) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	logrus.Debugf("Executing Open() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	relpath, err := filepath.Rel(h.Path, n.Path())
	if err != nil {
		return err
	}

	var resource = relpath

	flags := n.OpenFlags()

	switch resource {

	case ".":
		return nil

	case "product_uuid":
		if flags&syscall.O_WRONLY == syscall.O_WRONLY ||
			flags&syscall.O_RDWR == syscall.O_RDWR {
			return fuse.IOerror{Code: syscall.EACCES}
		}
		return nil
	}

	return n.Open()
}

func (h *SysDevicesVirtualDmiId) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	var resource = n.Name()

	logrus.Debugf("Executing Read() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	if req.Offset != 0 {
		return 0, nil
	}

	switch resource {

	case "product_uuid":
		return h.readProductUuid(n, req)
	}

	return readHostFs(h, n, req.Offset, &req.Data)
}

func (h *SysDevicesVirtualDmiId) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	return 0, nil
}

func (h *SysDevicesVirtualDmiId) ReadDirAll(
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

func (h *SysDevicesVirtualDmiId) GetName() string {
	return h.Name
}

func (h *SysDevicesVirtualDmiId) GetPath() string {
	return h.Path
}

func (h *SysDevicesVirtualDmiId) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *SysDevicesVirtualDmiId) GetEnabled() bool {
	return h.Enabled
}

func (h *SysDevicesVirtualDmiId) SetEnabled(b bool) {
	h.Enabled = b
}

func (h *SysDevicesVirtualDmiId) GetResourcesList() []string {

	var resources []string

	for resourceKey, resource := range h.EmuResourceMap {
		resource.Mutex.Lock()
		if !resource.Enabled {
			resource.Mutex.Unlock()
			continue
		}
		resource.Mutex.Unlock()

		// Resource name must be adjusted to account for the presence of the "id"
		// directory (i.e., ".") as one of the emulated resources.
		if resourceKey == "." {
			resources = append(resources, h.Path)
		} else {
			resources = append(resources, filepath.Join(h.GetPath(), resourceKey))
		}
	}

	return resources
}

func (h *SysDevicesVirtualDmiId) GetResourceMutex(n domain.IOnodeIface) *sync.Mutex {

	// Resource name must be adjusted to account for the possibility of caller asking
	// for the "id" directory itself (i.e., "." resource).
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

func (h *SysDevicesVirtualDmiId) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}

func (h *SysDevicesVirtualDmiId) readProductUuid(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	path := n.Path()
	cntr := req.Container

	cntr.Lock()
	defer cntr.Unlock()

	// Check if this product_uuid value has been initialized for this container.
	sz, err := cntr.Data(path, req.Offset, &req.Data)
	if err != nil && err != io.EOF {
		return 0, fuse.IOerror{Code: syscall.EINVAL}
	}

	if req.Offset == 0 && sz == 0 && err == io.EOF {
		// Create an artificial (but consistent) container uuid value and store it
		// in cache.
		cntrUuid := h.CreateCntrUuid(cntr)

		req.Data = []byte(cntrUuid + "\n")
		err = cntr.SetData(path, 0, req.Data)
		if err != nil {
			return 0, fuse.IOerror{Code: syscall.EINVAL}
		}
	}

	return len(req.Data), nil
}

// Method is public exclusively for unit-testing purposes.
func (h *SysDevicesVirtualDmiId) CreateCntrUuid(cntr domain.ContainerIface) string {

	hostUuid := h.Service.HostUuid()
	hostUuidPref := hostUuid[:timeFieldLen-1]

	// Pad the containerId with zeroes if it doesn't fill its slot.
	cntrIdPref := formatter.ContainerID{cntr.ID()}.String()
	if len(cntrIdPref) < nodeFieldLen {
		cntrIdPref = padRight(cntrIdPref, "0", nodeFieldLen)
	}

	return hostUuidPref + "-" + cntrIdPref
}
