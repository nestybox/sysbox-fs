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
// /sys/kernel handler
//
// The following sysfs nodes are exposed in order to satisfy applications that expect
// these resources to be present (and accessible) in the system; these nodes would
// appear as 'nobody:nogroup' when queried from a process that is hosted within a
// non-init user-ns. Having said that, be aware that the emulation being provided
// as part of this handler is very shallow: we are simply exposing these nodes, no
// inner content is displayed for security / isolation purposes.
//
// Emulated resources:
//
// * /sys/kernel/config
//
// * /sys/kernel/debug
//
// * /sys/kernel/tracing
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

	// If looked-up element hasn't been found by now, look into the actual
	// container rootfs.
	return h.Service.GetPassThroughHandler().Lookup(n, req)
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

	return h.Service.GetPassThroughHandler().Open(n, req)
}

func (h *SysKernel) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Read() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	return h.Service.GetPassThroughHandler().Read(n, req)
}

func (h *SysKernel) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Write() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	return h.Service.GetPassThroughHandler().Write(n, req)
}

func (h *SysKernel) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	var resource = n.Name()

	logrus.Debugf("Executing ReadDirAll() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	var fileEntries []os.FileInfo

	// Obtain relative path to the element being read.
	relpath, err := filepath.Rel(h.Path, n.Path())
	if err != nil {
		return nil, err
	}

	// Iterate through map of emulated components.
	for k, v := range h.EmuResourceMap {

		if relpath != filepath.Dir(k) {
			continue
		}

		info := &domain.FileInfo{
			Fname:    resource,
			Fmode:    v.Mode,
			FmodTime: time.Now(),
		}

		if v.Kind == domain.DirEmuResource {
			info.FisDir = true
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
