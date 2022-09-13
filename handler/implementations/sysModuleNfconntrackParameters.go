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
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
)

//
// /sys/module/nf_conntrack/parameters handler
//
// Emulated resources:
//
// * /sys/module/nf_conntrack/parameters/hashsize
//

type SysModuleNfconntrackParameters struct {
	domain.HandlerBase
}

var SysModuleNfconntrackParameters_Handler = &SysModuleNfconntrackParameters{
	domain.HandlerBase{
		Name:    "SysModuleNfconntrackParameters",
		Path:    "/sys/module/nf_conntrack/parameters",
		Enabled: true,
		EmuResourceMap: map[string]*domain.EmuResource{
			"hashsize": {
				Kind:    domain.FileEmuResource,
				Mode:    os.FileMode(uint32(0600)),
				Size:    4096,
				Enabled: true,
			},
		},
	},
}

func (h *SysModuleNfconntrackParameters) Lookup(
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
			Fsize:    v.Size,
		}

		if v.Kind == domain.DirEmuResource {
			info.FisDir = true
		}

		return info, nil
	}

	// Users should not be allowed to alter any of the non-emulated sysfs nodes.
	req.SkipIdRemap = true

	return n.Stat()
}

func (h *SysModuleNfconntrackParameters) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	return nil
}

func (h *SysModuleNfconntrackParameters) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	var resource = n.Name()

	logrus.Debugf("Executing Read() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	if req.Offset != 0 {
		return 0, nil
	}

	switch resource {
	case "hashsize":
		return readCntrData(h, n, req)
	}

	return readHostFs(h, n, req.Offset, &req.Data)
}

func (h *SysModuleNfconntrackParameters) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	var resource = n.Name()

	logrus.Debugf("Executing Write() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	if req.Offset != 0 {
		return 0, nil
	}

	switch resource {
	case "hashsize":
		return writeCntrData(h, n, req, writeToFs)
	}

	return writeHostFs(h, n, req.Offset, req.Data)
}

func (h *SysModuleNfconntrackParameters) ReadDirAll(
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

	// Create info entries for emulated resources under /sys/module/nf_conntrack/parameters
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

func (h *SysModuleNfconntrackParameters) GetName() string {
	return h.Name
}

func (h *SysModuleNfconntrackParameters) GetPath() string {
	return h.Path
}

func (h *SysModuleNfconntrackParameters) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *SysModuleNfconntrackParameters) GetEnabled() bool {
	return h.Enabled
}

func (h *SysModuleNfconntrackParameters) SetEnabled(b bool) {
	h.Enabled = b
}

func (h *SysModuleNfconntrackParameters) GetResourcesList() []string {

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

func (h *SysModuleNfconntrackParameters) GetResourceMutex(n domain.IOnodeIface) *sync.Mutex {
	resource, ok := h.EmuResourceMap[n.Name()]
	if !ok {
		return nil
	}

	return &resource.Mutex
}

func (h *SysModuleNfconntrackParameters) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
