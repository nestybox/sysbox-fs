// SPDX-License-Identifier: Apache-2.0

package implementations

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
)

var ProcCPUInfo_Handler = newProcCgroupFile("ProcCPUInfo", "/proc/cpuinfo", procCPUInfo)

func procCPUInfo(req *domain.HandlerRequest, reader, _ string) (string, error) {
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", req.Pid))
	if err != nil {
		return "", err
	}
	var allowed []uint64
	for line := range strings.SplitSeq(string(status), "\n") {
		if value, ok := strings.CutPrefix(line, "Cpus_allowed_list:"); ok {
			allowed, err = parseCPUList(strings.TrimSpace(value))
			if err != nil {
				return "", err
			}
			break
		}
	}
	if len(allowed) == 0 {
		return "", fuse.IOerror{Code: syscall.ENODATA}
	}
	n, err := quotaCPUCount(cgroupMount, reader, uint64(len(allowed)))
	if err != nil {
		return "", err
	}
	cpuinfo, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return "", err
	}
	return formatProcCPUInfo(string(cpuinfo), allowed[:n])
}

func parseCPUList(data string) ([]uint64, error) {
	var cpus []uint64
	for item := range strings.SplitSeq(data, ",") {
		start, end, isRange := strings.Cut(item, "-")
		first, err := strconv.ParseUint(start, 10, 32)
		if err != nil {
			return nil, err
		}
		last := first
		if isRange {
			last, err = strconv.ParseUint(end, 10, 32)
			if err != nil || last < first {
				return nil, fmt.Errorf("invalid CPU range %q", item)
			}
		}
		for cpu := first; cpu <= last; cpu++ {
			cpus = append(cpus, cpu)
		}
	}
	return cpus, nil
}

func quotaCPUCount(mount, reader string, count uint64) (uint64, error) {
	for path := reader; path != "/"; path = filepath.Dir(path) {
		data, err := os.ReadFile(filepath.Join(mount, path, "cpu.max"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return 0, err
		}
		fields := strings.Fields(string(data))
		if len(fields) != 2 {
			return 0, fmt.Errorf("invalid cpu.max %q", data)
		}
		if fields[0] == "max" {
			continue
		}
		quota, quotaErr := strconv.ParseUint(fields[0], 10, 64)
		period, periodErr := strconv.ParseUint(fields[1], 10, 64)
		if quotaErr != nil || periodErr != nil || quota == 0 || period == 0 {
			return 0, fmt.Errorf("invalid cpu.max %q", data)
		}
		// Report ceil(quota / period) without overflowing on addition.
		count = min(count, 1+(quota-1)/period)
	}
	return count, nil
}

func formatProcCPUInfo(data string, allowed []uint64) (string, error) {
	processors := make(map[uint64]string)
	for record := range strings.SplitSeq(data, "\n\n") {
		var fields strings.Builder
		var cpu uint64
		var found bool
		for line := range strings.SplitSeq(record, "\n") {
			key, value, _ := strings.Cut(line, ":")
			switch strings.TrimSpace(key) {
			case "processor":
				id, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
				if err == nil {
					cpu, found = id, true
				}
			case "vendor_id", "cpu family", "model", "model name", "stepping", "flags", "bugs",
				"Features", "CPU implementer", "CPU architecture", "CPU variant", "CPU part", "CPU revision",
				"isa", "mmu", "uarch":
				fields.WriteString(line + "\n")
			}
		}
		if found {
			processors[cpu] = fields.String()
		}
	}
	var out strings.Builder
	for index, cpu := range allowed {
		fields, ok := processors[cpu]
		if !ok {
			return "", fuse.IOerror{Code: syscall.ENODATA}
		}
		// Virtual processor IDs are contiguous and omit host package topology.
		fmt.Fprintf(&out, "processor\t: %d\n%s\n", index, fields)
	}
	return out.String(), nil
}
