// SPDX-License-Identifier: Apache-2.0

package implementations

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/nestybox/sysbox-fs/domain"
)

var (
	ProcCgroups_Handler   = newProcCgroupFile("ProcCgroups", "/proc/cgroups", procCgroups)
	ProcDiskstats_Handler = newProcCgroupFile("ProcDiskstats", "/proc/diskstats", procDiskstats)
	ProcStat_Handler      = newProcCgroupFile("ProcStat", "/proc/stat", procStat)
)

func procStat(req *domain.HandlerRequest, reader, _ string) (string, error) {
	data, err := os.ReadFile(filepath.Join(cgroupMount, reader, "cpu.stat"))
	if err != nil {
		return "", err
	}
	return formatProcStat(string(data), req.Container.Ctime().Unix())
}

func formatProcStat(data string, bootTime int64) (string, error) {
	user, err := cgroupCounter(data, "user_usec")
	if err != nil {
		return "", err
	}
	system, err := cgroupCounter(data, "system_usec")
	if err != nil {
		return "", err
	}
	// Linux reports USER_HZ ticks (100 per second). cpu.stat only provides
	// aggregate user and system time, so leave the other CPU fields at zero.
	return fmt.Sprintf("cpu  %d 0 %d 0 0 0 0 0 0 0\nbtime %d\n", user/10000, system/10000, bootTime), nil
}

func procCgroups(_ *domain.HandlerRequest, reader, _ string) (string, error) {
	dir := filepath.Join(cgroupMount, reader)
	controllers, err := os.ReadFile(filepath.Join(dir, "cgroup.controllers"))
	if err != nil {
		return "", err
	}
	stats, err := os.ReadFile(filepath.Join(dir, "cgroup.stat"))
	if err != nil {
		return "", err
	}
	descendants, err := cgroupCounter(string(stats), "nr_descendants")
	if err != nil {
		return "", err
	}
	var out strings.Builder
	out.WriteString("#subsys_name\thierarchy\tnum_cgroups\tenabled\n")
	for _, controller := range strings.Fields(string(controllers)) {
		// Keep the v1 names expected by consumers of this legacy file.
		switch controller {
		case "cpu":
			fmt.Fprintf(&out, "cpuacct\t0\t%d\t1\n", descendants+1)
		case "io":
			controller = "blkio"
		}
		fmt.Fprintf(&out, "%s\t0\t%d\t1\n", controller, descendants+1)
	}
	return out.String(), nil
}

func procDiskstats(_ *domain.HandlerRequest, reader, _ string) (string, error) {
	data, err := os.ReadFile(filepath.Join(cgroupMount, reader, "io.stat"))
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return formatProcDiskstats(string(data), "/sys/dev/block")
}

func formatProcDiskstats(data, blockDevices string) (string, error) {
	var out strings.Builder
	lines := strings.Split(strings.TrimSpace(data), "\n")
	slices.Sort(lines)
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		major, minor, _ := strings.Cut(fields[0], ":")
		majorID, majorErr := strconv.ParseUint(major, 10, 32)
		minorID, minorErr := strconv.ParseUint(minor, 10, 32)
		if majorErr != nil || minorErr != nil {
			return "", fmt.Errorf("invalid io.stat device %q", fields[0])
		}
		device, err := os.Readlink(filepath.Join(blockDevices, fields[0]))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return "", err
		}
		var counts = make(map[string]uint64, 6)
		for _, field := range fields[1:] {
			key, val, _ := strings.Cut(field, "=")
			switch key {
			case "rios", "rbytes", "wios", "wbytes", "dios", "dbytes":
				count, err := strconv.ParseUint(val, 10, 64)
				if err != nil {
					return "", err
				}
				counts[key] = count
			}
		}
		// Diskstats sectors are always 512 bytes. io.stat has no timing,
		// merge, in-flight, or flush counters.
		fmt.Fprintf(&out, "%4d %7d %s %d 0 %d 0 %d 0 %d 0 0 0 0 %d 0 %d 0 0 0\n",
			majorID, minorID, filepath.Base(device), counts["rios"], counts["rbytes"]/512,
			counts["wios"], counts["wbytes"]/512, counts["dios"], counts["dbytes"]/512)
	}
	return out.String(), nil
}

func cgroupCounter(data, key string) (uint64, error) {
	for line := range strings.SplitSeq(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == key {
			return strconv.ParseUint(fields[1], 10, 64)
		}
	}
	return 0, fmt.Errorf("missing cgroup counter %q", key)
}
