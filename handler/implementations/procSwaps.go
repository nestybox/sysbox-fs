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
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
)

//
// /proc/swaps handler
//

// /proc/swaps static header
var swapsHeader = "Filename                                Type            Size    Used    Priority"

type ProcSwaps struct {
	domain.HandlerBase
}

var ProcSwaps_Handler = &ProcSwaps{
	domain.HandlerBase{
		Name:    "ProcSwaps",
		Path:    "/proc/swaps",
		Enabled: true,
	},
}

func (h *ProcSwaps) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	var resource = n.Name()

	logrus.Debugf("Executing Lookup() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	info := &domain.FileInfo{
		Fname:    resource,
		Fmode:    os.FileMode(uint32(0444)),
		FmodTime: time.Now(),
	}

	return info, nil
}

func (h *ProcSwaps) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	logrus.Debugf("Executing Open() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	flags := n.OpenFlags()

	if flags&syscall.O_WRONLY == syscall.O_WRONLY ||
		flags&syscall.O_RDWR == syscall.O_RDWR {
		return fuse.IOerror{Code: syscall.EACCES}
	}

	return nil
}

func (h *ProcSwaps) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Read() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	return h.readSwaps(n, req)
}

func (h *ProcSwaps) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Write() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	return 0, nil
}

func (h *ProcSwaps) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	var resource = n.Name()

	logrus.Debugf("Executing ReadDirAll() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	return nil, nil
}

func (h *ProcSwaps) ReadLink(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (string, error) {

	logrus.Debugf("Executing ReadLink() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	return "", nil
}

func (h *ProcSwaps) GetName() string {
	return h.Name
}

func (h *ProcSwaps) GetPath() string {
	return h.Path
}

func (h *ProcSwaps) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *ProcSwaps) GetEnabled() bool {
	return h.Enabled
}

func (h *ProcSwaps) SetEnabled(b bool) {
	h.Enabled = b
}

func (h *ProcSwaps) GetResourcesList() []string {

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

func (h *ProcSwaps) GetResourceMutex(n domain.IOnodeIface) *sync.Mutex {
	resource, ok := h.EmuResourceMap[n.Name()]
	if !ok {
		return nil
	}

	return &resource.Mutex
}

func (h *ProcSwaps) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}

func (h *ProcSwaps) readSwaps(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing %v Read() method", h.Name)

	if req.Offset > 0 {
		return 0, io.EOF
	}

	// Pretend swapping is off
	//
	// TODO: fix this once Sysbox intercepts the swapon() and swapoff() syscalls.

	req.Data = []byte(swapsHeader + "\n")

	return len(req.Data), nil
}
