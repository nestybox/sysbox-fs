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
	"sync"
	"time"

	"github.com/nestybox/sysbox-fs/domain"

	"github.com/sirupsen/logrus"
)

//
// /proc/sys handler
//
// Handles all accesses to /proc/sys. Currently just a thin wrapper over the
// pass-through handler.
//

type ProcSys struct {
	domain.HandlerBase
}

var ProcSys_Handler = &ProcSys{
	domain.HandlerBase{
		Name:    "ProcSys",
		Path:    "/proc/sys",
		Enabled: true,
		EmuResourceMap: map[string]*domain.EmuResource{
			".": {
				Kind:    domain.DirEmuResource,
				Mode:    os.ModeDir | os.FileMode(uint32(0555)),
				Enabled: true,
			},
		},
	},
}

func (h *ProcSys) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	relpath, err := filepath.Rel(h.Path, n.Path())
	if err != nil {
		return nil, err
	}

	var resource = relpath

	if v, ok := h.EmuResourceMap[resource]; ok {
		if resource == "." {
			resource = "sys"
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

	return h.Service.GetPassThroughHandler().Lookup(n, req)
}

func (h *ProcSys) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	logrus.Debugf("Executing Open() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	return h.Service.GetPassThroughHandler().Open(n, req)
}

func (h *ProcSys) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Read() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	return h.Service.GetPassThroughHandler().Read(n, req)
}

func (h *ProcSys) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Write() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	return h.Service.GetPassThroughHandler().Write(n, req)
}

func (h *ProcSys) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	logrus.Debugf("Executing ReadDirAll() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	return h.Service.GetPassThroughHandler().ReadDirAll(n, req)
}

func (h *ProcSys) ReadLink(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (string, error) {

	logrus.Debugf("Executing ReadLink() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	return h.Service.GetPassThroughHandler().ReadLink(n, req)
}

func (h *ProcSys) GetName() string {
	return h.Name
}

func (h *ProcSys) GetPath() string {
	return h.Path
}

func (h *ProcSys) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *ProcSys) GetEnabled() bool {
	return h.Enabled
}

func (h *ProcSys) SetEnabled(b bool) {
	h.Enabled = b
}

func (h *ProcSys) GetResourcesList() []string {

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

func (h *ProcSys) GetResourceMutex(n domain.IOnodeIface) *sync.Mutex {
	resource, ok := h.EmuResourceMap[n.Name()]
	if !ok {
		return nil
	}

	return &resource.Mutex
}

func (h *ProcSys) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
