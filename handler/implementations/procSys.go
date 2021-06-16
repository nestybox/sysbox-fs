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

	"github.com/nestybox/sysbox-fs/domain"

	"github.com/sirupsen/logrus"
)

//
// /proc/sys/ handler
//
// Currently just a thin wrapper over the pass-through handler to serve accesses
// to the content of the "/proc/sys/" folder. The "/proc/sys" node itself is
// served as part of the "proc" handler.
//

type ProcSys struct {
	domain.HandlerBase
}

var ProcSys_Handler = &ProcSys{
	domain.HandlerBase{
		Name:    "ProcSys",
		Path:    "/proc/sys/",
		Enabled: true,
	},
}

func (h *ProcSys) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() for Req ID=%#x, %v handler, resource %s",
		req.ID, h.Name, n.Name())

	return h.Service.GetPassThroughHandler().Lookup(n, req)
}

func (h *ProcSys) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	logrus.Debugf("Executing Open() for Req ID=%#x, %v handler, resource %s",
		req.ID, h.Name, n.Name())

	return h.Service.GetPassThroughHandler().Open(n, req)
}

func (h *ProcSys) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Read() for Req ID=%#x, %v handler, resource %s",
		req.ID, h.Name, n.Name())

	return h.Service.GetPassThroughHandler().Read(n, req)
}

func (h *ProcSys) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Write() for Req ID=%#x, %v handler, resource %s",
		req.ID, h.Name, n.Name())

	return h.Service.GetPassThroughHandler().Write(n, req)
}

func (h *ProcSys) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	logrus.Debugf("Executing ReadDirAll() for Req ID=%#x, %v handler, resource %s",
		req.ID, h.Name, n.Name())

	return h.Service.GetPassThroughHandler().ReadDirAll(n, req)
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

func (h *ProcSys) GetResourceMutex(s string) *sync.Mutex {
	resource, ok := h.EmuResourceMap[s]
	if !ok {
		return nil
	}

	return &resource.Mutex
}

func (h *ProcSys) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
