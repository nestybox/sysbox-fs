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
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
)

//
// /proc/meminfo handler
//
// Shows the memory limit of the reading process' cgroup (memory.max of the
// cgroup or its closest limited ancestor) as the total memory, and that
// cgroup's usage and memory.stat counters in the fields derived from them.
// Fields with no cgroup equivalent keep their host values. When no limit
// applies, or it exceeds the host's memory, the host file is shown as-is.
//

type ProcMeminfo struct {
	domain.HandlerBase
}

var ProcMeminfo_Handler = &ProcMeminfo{
	domain.HandlerBase{
		Name:    "ProcMeminfo",
		Path:    "/proc/meminfo",
		Enabled: true,
	},
}

// meminfo fields that mirror memory.stat counters of the same meaning.
var meminfoMemoryStat = []struct {
	field    string
	counters []string
}{
	{"Cached", []string{"file"}},
	{"SwapCached", []string{"swapcached"}},
	{"Active", []string{"active_anon", "active_file"}},
	{"Inactive", []string{"inactive_anon", "inactive_file"}},
	{"Active(anon)", []string{"active_anon"}},
	{"Inactive(anon)", []string{"inactive_anon"}},
	{"Active(file)", []string{"active_file"}},
	{"Inactive(file)", []string{"inactive_file"}},
	{"Unevictable", []string{"unevictable"}},
	{"Dirty", []string{"file_dirty"}},
	{"Writeback", []string{"file_writeback"}},
	{"AnonPages", []string{"anon"}},
	{"Mapped", []string{"file_mapped"}},
	{"Shmem", []string{"shmem"}},
	{"KReclaimable", []string{"slab_reclaimable"}},
	{"Slab", []string{"slab"}},
	{"SReclaimable", []string{"slab_reclaimable"}},
	{"SUnreclaim", []string{"slab_unreclaimable"}},
	{"KernelStack", []string{"kernel_stack"}},
	{"PageTables", []string{"pagetables"}},
	{"AnonHugePages", []string{"anon_thp"}},
	{"ShmemHugePages", []string{"shmem_thp"}},
	{"FileHugePages", []string{"file_thp"}},
}

func (h *ProcMeminfo) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	return n.Lstat()
}

func (h *ProcMeminfo) Open(
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

func (h *ProcMeminfo) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Read() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	return readSnapshot(req, h.Path, func() ([]byte, error) {
		host, err := fs.ReadFile(hostFs, "proc/meminfo")
		if err != nil {
			return nil, err
		}
		if cg, err := cgroupV2Path(hostFs, req.Pid); err == nil {
			return []byte(cgroupMeminfo(hostFs, cg, string(host))), nil
		}
		return host, nil
	})
}

func (h *ProcMeminfo) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	return 0, nil
}

func (h *ProcMeminfo) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	return nil, nil
}

func (h *ProcMeminfo) ReadLink(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (string, error) {

	return "", nil
}

func (h *ProcMeminfo) GetName() string {
	return h.Name
}

func (h *ProcMeminfo) GetPath() string {
	return h.Path
}

func (h *ProcMeminfo) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *ProcMeminfo) GetEnabled() bool {
	return h.Enabled
}

func (h *ProcMeminfo) SetEnabled(b bool) {
	h.Enabled = b
}

func (h *ProcMeminfo) GetResourcesList() []string {

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

func (h *ProcMeminfo) GetResourceMutex(n domain.IOnodeIface) *sync.Mutex {
	resource, ok := h.EmuResourceMap[n.Name()]
	if !ok {
		return nil
	}

	return &resource.Mutex
}

func (h *ProcMeminfo) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}

// cgroupMeminfo returns the host's /proc/meminfo content as seen by a process
// in the given cgroup.
func cgroupMeminfo(fsys fs.FS, cg, host string) string {
	hostKb := parseMeminfo(host)

	limit, limitCg, ok := cgroupMemLimit(fsys, cg, "memory.max")
	if !ok || limit/1024 >= hostKb["MemTotal"] {
		return host
	}

	statData, _ := readCgroupFile(fsys, limitCg, "memory.stat")
	stat := parseMemoryStat(statData)
	usage := readCgroupUint(fsys, limitCg, "memory.current")
	workingSet := subSat(usage, stat["inactive_file"])

	kb := map[string]uint64{
		"MemTotal":     limit / 1024,
		"MemFree":      min(hostKb["MemFree"], subSat(limit, usage)/1024),
		"MemAvailable": min(hostKb["MemAvailable"], subSat(limit, workingSet)/1024),
		"Buffers":      0,
	}

	for _, m := range meminfoMemoryStat {
		var bytes uint64
		for _, counter := range m.counters {
			bytes += stat[counter]
		}
		kb[m.field] = bytes / 1024
	}

	swapTotal := hostKb["SwapTotal"]
	swapCg := limitCg
	if swapLimit, swapLimitCg, ok := cgroupMemLimit(fsys, cg, "memory.swap.max"); ok {
		swapTotal = min(swapTotal, swapLimit/1024)
		swapCg = swapLimitCg
	}
	swapUsage := readCgroupUint(fsys, swapCg, "memory.swap.current")
	kb["SwapTotal"] = swapTotal
	kb["SwapFree"] = min(hostKb["SwapFree"], subSat(swapTotal, swapUsage/1024))

	return rewriteMeminfo(host, kb)
}

// parseMeminfo returns the values (in kB) of the given /proc/meminfo content.
func parseMeminfo(content string) map[string]uint64 {
	kb := make(map[string]uint64)

	for _, line := range strings.Split(content, "\n") {
		key, rest, ok := strings.Cut(line, ":")
		fields := strings.Fields(rest)
		if !ok || len(fields) == 0 {
			continue
		}
		if v, err := strconv.ParseUint(fields[0], 10, 64); err == nil {
			kb[key] = v
		}
	}

	return kb
}

// parseMemoryStat returns the counters of the given memory.stat content.
func parseMemoryStat(content string) map[string]uint64 {
	stat := make(map[string]uint64)

	for _, line := range strings.Split(content, "\n") {
		key, val, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		if v, err := strconv.ParseUint(val, 10, 64); err == nil {
			stat[key] = v
		}
	}

	return stat
}

// rewriteMeminfo replaces the values of the given fields in the given
// /proc/meminfo content, keeping the kernel's layout.
func rewriteMeminfo(content string, kb map[string]uint64) string {
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		key, _, _ := strings.Cut(line, ":")
		if v, ok := kb[key]; ok {
			lines[i] = fmt.Sprintf("%-16s%8d kB", key+":", v)
		}
	}

	return strings.Join(lines, "\n")
}

func subSat(a, b uint64) uint64 {
	if a < b {
		return 0
	}
	return a - b
}
