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
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
)

//
// /sys handler
//

type Sys struct {
	domain.HandlerBase
}

var Sys_Handler = &Sys{
	domain.HandlerBase{
		Name:    "Sys",
		Path:    "/sys",
		Enabled: true,
		EmuResourceMap: map[string]*domain.EmuResource{
			"kernel": {
				Kind:    domain.DirEmuResource,
				Mode:    os.ModeDir | os.FileMode(uint32(0755)),
				Enabled: true,
			},
		},
	},
}

func (h *Sys) Lookup(
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

		if v.Kind == domain.DirEmuResource {
			info.FisDir = true
		}

		return info, nil
	}

	return n.Stat()
}

func (h *Sys) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	logrus.Debugf("Executing Open() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	return nil
}

func (h *Sys) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Read() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	return 0, nil
}

func (h *Sys) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Write() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	return 0, nil
}

func (h *Sys) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	var resource = n.Name()

	logrus.Debugf("Executing ReadDirAll() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	switch resource {
	case "kernel":
		hk, ok := h.Service.FindHandler("/sys/kernel/")
		if !ok {
			return nil, fmt.Errorf("handler %s not found in handlerDB", resource)
		}
		return hk.ReadDirAll(n, req)
	}

	return nil, nil
}

func (h *Sys) GetName() string {
	return h.Name
}

func (h *Sys) GetPath() string {
	return h.Path
}

func (h *Sys) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *Sys) GetEnabled() bool {
	return h.Enabled
}

func (h *Sys) SetEnabled(b bool) {
	h.Enabled = b
}

func (h *Sys) GetResourcesList() []string {

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

func (h *Sys) GetResourceMutex(n domain.IOnodeIface) *sync.Mutex {
	resource, ok := h.EmuResourceMap[n.Name()]
	if !ok {
		return nil
	}

	return &resource.Mutex
}

func (h *Sys) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
