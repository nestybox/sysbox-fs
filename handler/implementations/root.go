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

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
)

//
// root dir (/) dummy handler
//
// Since the sysbox-fs root dir is not mounted inside a system container,
// accesses to it are only possible from host level (e.g., via /var/lib/sysboxfs/<container-id>/).
//
// Such accesses typically occur when sysbox-runc is creating the container and
// it bind-mounts sysbox-fs to subdirs under the container's "/proc" or "/sys"
// (e.g., /proc/uptime, /proc/sys, etc); as part of the bind-mount, the kernel
// walks the bind-source path, which results in sysbox-fs receiving lookups into
// this handler. Thus, this handler only serves such lookups; all other handler
// methods are purposefully dummy, as we generally want to ignore accesses to
// sysbox-fs from host level.

type Root struct {
	domain.HandlerBase
}

var Root_Handler = &Root{
	domain.HandlerBase{
		Name:    "root",
		Path:    "/",
		Enabled: true,
	},
}

func (h *Root) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	var resource = n.Name()

	logrus.Debugf("Executing Lookup() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	return n.Stat()
}

func (h *Root) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	return nil
}

func (h *Root) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	return 0, nil
}

func (h *Root) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	return 0, nil
}

func (h *Root) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	var resource = n.Name()

	logrus.Debugf("Executing ReadDirAll() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	return nil, nil
}

func (h *Root) GetName() string {
	return h.Name
}

func (h *Root) GetPath() string {
	return h.Path
}

func (h *Root) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *Root) GetEnabled() bool {
	return h.Enabled
}

func (h *Root) SetEnabled(b bool) {
	h.Enabled = b
}

func (h *Root) GetResourcesList() []string {

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

func (h *Root) GetResourceMutex(n domain.IOnodeIface) *sync.Mutex {
	resource, ok := h.EmuResourceMap[n.Name()]
	if !ok {
		return nil
	}

	return &resource.Mutex
}

func (h *Root) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
