//
// Copyright 2026 Nestybox, Inc.
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
	"syscall"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
)

//
// /sys/devices/system/cpu/online handler
//
// Lists the CPUs available to the reading process, the same ones shown in
// /proc/cpuinfo. glibc's get_nprocs() (and thus sysconf(_SC_NPROCESSORS_ONLN),
// std::thread::hardware_concurrency(), Python's os.cpu_count(), etc.) counts
// the CPUs in this file.
//

type SysDevicesSystemCpuOnline struct {
	domain.HandlerBase
}

var SysDevicesSystemCpuOnline_Handler = &SysDevicesSystemCpuOnline{
	domain.HandlerBase{
		Name:    "SysDevicesSystemCpuOnline",
		Path:    "/sys/devices/system/cpu/online",
		Enabled: true,
	},
}

func (h *SysDevicesSystemCpuOnline) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	return n.Lstat()
}

func (h *SysDevicesSystemCpuOnline) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (bool, error) {

	logrus.Debugf("Executing Open() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	flags := n.OpenFlags()

	if flags&syscall.O_WRONLY == syscall.O_WRONLY ||
		flags&syscall.O_RDWR == syscall.O_RDWR {
		return false, fuse.IOerror{Code: syscall.EACCES}
	}

	return false, nil
}

func (h *SysDevicesSystemCpuOnline) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Read() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	return readSnapshot(req, h.Path, func() ([]byte, error) {
		cpus, _, err := readerCpus(hostFs, req)
		if err != nil {
			return nil, err
		}
		return []byte(formatCpuList(cpus) + "\n"), nil
	})
}

func (h *SysDevicesSystemCpuOnline) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	return 0, nil
}

func (h *SysDevicesSystemCpuOnline) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	return nil, nil
}

func (h *SysDevicesSystemCpuOnline) ReadLink(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (string, error) {

	return "", nil
}

func (h *SysDevicesSystemCpuOnline) GetName() string {
	return h.Name
}

func (h *SysDevicesSystemCpuOnline) GetPath() string {
	return h.Path
}

func (h *SysDevicesSystemCpuOnline) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *SysDevicesSystemCpuOnline) GetEnabled() bool {
	return h.Enabled
}

func (h *SysDevicesSystemCpuOnline) SetEnabled(b bool) {
	h.Enabled = b
}

func (h *SysDevicesSystemCpuOnline) GetResourcesList() []string {

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

func (h *SysDevicesSystemCpuOnline) GetResourceMutex(n domain.IOnodeIface) *sync.Mutex {
	resource, ok := h.EmuResourceMap[n.Name()]
	if !ok {
		return nil
	}

	return &resource.Mutex
}

func (h *SysDevicesSystemCpuOnline) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
