// SPDX-License-Identifier: Apache-2.0

package implementations

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/nestybox/sysbox-fs/cgroup"
	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
)

var ProcCPUInfo_Handler = newProcCgroupFile("ProcCPUInfo", "/proc/cpuinfo", procCPUInfo)

func procCPUInfo(req *domain.HandlerRequest, reader, _ string) (string, error) {
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", req.Pid))
	if err != nil {
		return "", err
	}
	allowed, err := cgroup.CPUs(status, reader)
	if err != nil {
		return "", err
	}
	cpuinfo, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return "", err
	}
	return formatProcCPUInfo(string(cpuinfo), allowed)
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
	for _, cpu := range allowed {
		fields, ok := processors[cpu]
		if !ok {
			return "", fuse.IOerror{Code: syscall.ENODATA}
		}
		fmt.Fprintf(&out, "processor\t: %d\n%s\n", cpu, fields)
	}
	return out.String(), nil
}
