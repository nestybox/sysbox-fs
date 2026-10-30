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
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
)

//
// /proc/cpuinfo handler
//
// Shows only the processor entries of the CPUs available to the reading
// process: its effective cpuset, trimmed to its CPU quota rounded up (see
// cgroupCpus()). CPUs keep their host numbering, so they remain valid targets
// for sched_setaffinity(). Formats without per-processor entries (e.g., s390x)
// are shown as-is.
//

type ProcCpuinfo struct {
	domain.HandlerBase
}

var ProcCpuinfo_Handler = &ProcCpuinfo{
	domain.HandlerBase{
		Name:    "ProcCpuinfo",
		Path:    "/proc/cpuinfo",
		Enabled: true,
	},
}

func (h *ProcCpuinfo) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	return n.Lstat()
}

func (h *ProcCpuinfo) Open(
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

func (h *ProcCpuinfo) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Read() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	host, err := fs.ReadFile(hostFs, "proc/cpuinfo")
	if err != nil {
		return 0, err
	}

	content := host
	cpus, hostCpus, err := readerCpus(hostFs, req)
	if err == nil && !slices.Equal(cpus, hostCpus) {
		content = []byte(filterCpuinfo(string(host), cpus))
	}

	return readAtOffset(req, content)
}

func (h *ProcCpuinfo) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	return 0, nil
}

func (h *ProcCpuinfo) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	return nil, nil
}

func (h *ProcCpuinfo) ReadLink(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (string, error) {

	return "", nil
}

func (h *ProcCpuinfo) GetName() string {
	return h.Name
}

func (h *ProcCpuinfo) GetPath() string {
	return h.Path
}

func (h *ProcCpuinfo) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *ProcCpuinfo) GetEnabled() bool {
	return h.Enabled
}

func (h *ProcCpuinfo) SetEnabled(b bool) {
	h.Enabled = b
}

func (h *ProcCpuinfo) GetResourcesList() []string {

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

func (h *ProcCpuinfo) GetResourceMutex(n domain.IOnodeIface) *sync.Mutex {
	resource, ok := h.EmuResourceMap[n.Name()]
	if !ok {
		return nil
	}

	return &resource.Mutex
}

func (h *ProcCpuinfo) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}

// filterCpuinfo keeps the processor entries of the given CPUs in the given
// /proc/cpuinfo content, along with any entry that does not describe a
// processor.
func filterCpuinfo(content string, cpus []int) string {
	body := strings.TrimRight(content, "\n")
	trailer := content[len(body):]

	var kept []string
	found := false

	for _, entry := range strings.Split(body, "\n\n") {
		if cpu, ok := cpuinfoProcessor(entry); ok {
			found = true
			if !slices.Contains(cpus, cpu) {
				continue
			}
		}
		kept = append(kept, entry)
	}

	if !found {
		return content
	}

	return strings.Join(kept, "\n\n") + trailer
}

// cpuinfoProcessor returns the CPU described by the given /proc/cpuinfo entry,
// if it starts with a "processor : <cpu>" line.
func cpuinfoProcessor(entry string) (int, bool) {
	line, _, _ := strings.Cut(entry, "\n")
	key, val, ok := strings.Cut(line, ":")
	if !ok || strings.TrimSpace(key) != "processor" {
		return 0, false
	}

	cpu, err := strconv.Atoi(strings.TrimSpace(val))
	return cpu, err == nil
}
