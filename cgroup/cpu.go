// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// CPUs returns the task's real CPU IDs from its proc status, limited by the
// cgroup's quota and any tighter ancestor quotas.
func CPUs(status []byte, reader string) ([]uint64, error) {
	for line := range strings.SplitSeq(string(status), "\n") {
		if value, ok := strings.CutPrefix(line, "Cpus_allowed_list:"); ok {
			allowed, err := parseCPUList(strings.TrimSpace(value))
			if err != nil {
				return nil, err
			}
			n, err := quotaCPUCount(Mount, reader, uint64(len(allowed)))
			if err != nil {
				return nil, err
			}
			return allowed[:n], nil
		}
	}
	return nil, syscall.ENODATA
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
