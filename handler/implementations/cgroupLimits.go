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
	"io"
	"io/fs"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/nestybox/sysbox-fs/domain"
)

//
// Helpers to derive the memory and CPU resources available to a process from
// its cgroup v2 hierarchy. Used by the handlers that virtualize
// /proc/meminfo, /proc/cpuinfo and /sys/devices/system/cpu/online, so that
// programs sizing themselves from these files (thread pools, caches, model
// loaders, etc.) see the container's limits rather than the host's resources.
//
// On cgroup v1 hosts no limits are found and the host files are shown as-is.
//

// Host file system as seen by sysbox-fs (replaced by unit tests).
var hostFs fs.FS = os.DirFS("/")

// cgroupV2Path returns the cgroup v2 path of the given process, relative to
// the host's cgroup root.
func cgroupV2Path(fsys fs.FS, pid uint32) (string, error) {
	data, err := fs.ReadFile(fsys, fmt.Sprintf("proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}

	for _, line := range strings.Split(string(data), "\n") {
		if cg, ok := strings.CutPrefix(line, "0::"); ok {
			return cg, nil
		}
	}

	return "", fmt.Errorf("process %d is not in a cgroup v2 hierarchy", pid)
}

// cgroupAncestors returns the given cgroup followed by all its ancestors, up
// to the cgroup root.
func cgroupAncestors(cg string) []string {
	var cgs []string

	for cg = path.Clean("/" + cg); ; cg = path.Dir(cg) {
		cgs = append(cgs, cg)
		if cg == "/" {
			return cgs
		}
	}
}

func readCgroupFile(fsys fs.FS, cg, file string) (string, error) {
	data, err := fs.ReadFile(fsys, path.Join("sys/fs/cgroup", cg, file))
	return strings.TrimSpace(string(data)), err
}

func readCgroupUint(fsys fs.FS, cg, file string) uint64 {
	val, _ := readCgroupFile(fsys, cg, file)
	n, _ := strconv.ParseUint(val, 10, 64)
	return n
}

// cgroupMemLimit returns the lowest limit set in the given file (e.g.,
// "memory.max") by the cgroup or any of its ancestors, along with the cgroup
// that sets it. Returns ok == false when no cgroup sets a limit.
func cgroupMemLimit(fsys fs.FS, cg, file string) (limit uint64, limitCg string, ok bool) {
	for _, c := range cgroupAncestors(cg) {
		val, err := readCgroupFile(fsys, c, file)
		if err != nil || val == "max" {
			continue
		}
		v, err := strconv.ParseUint(val, 10, 64)
		if err != nil {
			continue
		}
		if !ok || v < limit {
			limit, limitCg, ok = v, c, true
		}
	}

	return limit, limitCg, ok
}

// cgroupCpuQuota returns the lowest CPU quota set by the cgroup or any of its
// ancestors, rounded up to whole CPUs. Returns 0 when no quota is set.
func cgroupCpuQuota(fsys fs.FS, cg string) int {
	var cpus int

	for _, c := range cgroupAncestors(cg) {
		val, err := readCgroupFile(fsys, c, "cpu.max")
		if err != nil {
			continue
		}
		fields := strings.Fields(val)
		if len(fields) != 2 || fields[0] == "max" {
			continue
		}
		quota, err1 := strconv.ParseUint(fields[0], 10, 64)
		period, err2 := strconv.ParseUint(fields[1], 10, 64)
		if err1 != nil || err2 != nil || quota == 0 || period == 0 {
			continue
		}
		n := int((quota + period - 1) / period)
		if cpus == 0 || n < cpus {
			cpus = n
		}
	}

	return cpus
}

// cgroupCpus returns the CPUs a process in the given cgroup may run on (its
// effective cpuset), trimmed to the cgroup's CPU quota rounded up. This
// matches the CPU count that cgroup-aware runtimes (JVM, Go, libuv) derive.
func cgroupCpus(fsys fs.FS, cg string, hostCpus []int) []int {
	cpus := hostCpus

	for _, c := range cgroupAncestors(cg) {
		val, err := readCgroupFile(fsys, c, "cpuset.cpus.effective")
		if err != nil {
			continue
		}
		if set, err := parseCpuList(val); err == nil && len(set) > 0 {
			cpus = set
		}
		break
	}

	if n := cgroupCpuQuota(fsys, cg); n > 0 && n < len(cpus) {
		cpus = cpus[:n]
	}

	return cpus
}

// hostOnlineCpus returns the host's online CPUs.
func hostOnlineCpus(fsys fs.FS) ([]int, error) {
	data, err := fs.ReadFile(fsys, "sys/devices/system/cpu/online")
	if err != nil {
		return nil, err
	}
	return parseCpuList(string(data))
}

// readerCpus returns the CPUs available to the process issuing the request,
// along with all of the host's online CPUs.
func readerCpus(fsys fs.FS, req *domain.HandlerRequest) (cpus, hostCpus []int, err error) {
	hostCpus, err = hostOnlineCpus(fsys)
	if err != nil {
		return nil, nil, err
	}

	cg, err := cgroupV2Path(fsys, req.Pid)
	if err != nil {
		return hostCpus, hostCpus, nil
	}

	return cgroupCpus(fsys, cg, hostCpus), hostCpus, nil
}

// parseCpuList parses a kernel CPU list (e.g., "0-3,8,10-11").
func parseCpuList(s string) ([]int, error) {
	var cpus []int

	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}

	for _, part := range strings.Split(s, ",") {
		lo, hi, isRange := strings.Cut(part, "-")
		first, err := strconv.Atoi(lo)
		if err != nil {
			return nil, err
		}
		last := first
		if isRange {
			if last, err = strconv.Atoi(hi); err != nil {
				return nil, err
			}
		}
		for cpu := first; cpu <= last; cpu++ {
			cpus = append(cpus, cpu)
		}
	}

	return cpus, nil
}

// formatCpuList formats a sorted list of CPUs the way the kernel does (e.g.,
// "0-3,8,10-11").
func formatCpuList(cpus []int) string {
	var parts []string

	for i := 0; i < len(cpus); {
		j := i
		for j+1 < len(cpus) && cpus[j+1] == cpus[j]+1 {
			j++
		}
		if i == j {
			parts = append(parts, strconv.Itoa(cpus[i]))
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", cpus[i], cpus[j]))
		}
		i = j + 1
	}

	return strings.Join(parts, ",")
}

// readAtOffset copies the part of the given content found at the request's
// offset into the request's buffer.
func readAtOffset(req *domain.HandlerRequest, content []byte) (int, error) {
	if req.Offset >= int64(len(content)) {
		return 0, io.EOF
	}
	return copy(req.Data, content[req.Offset:]), nil
}
