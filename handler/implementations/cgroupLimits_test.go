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
	"io"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/sysio"
)

const (
	testPid      = 4242
	testPodCg    = "/kubepods.slice/kubepods-burstable.slice/pod1"
	testCntrCg   = testPodCg + "/cri-containerd-abc.scope"
	testHostCpus = "0-3\n"
)

const testHostMeminfo = `MemTotal:       65835592 kB
MemFree:        20000000 kB
MemAvailable:   30179080 kB
Buffers:          500000 kB
Cached:          9000000 kB
SwapCached:            0 kB
Active:         12000000 kB
Inactive:        8000000 kB
Active(anon):    7000000 kB
Inactive(anon):  1000000 kB
Active(file):    5000000 kB
Inactive(file):  7000000 kB
SwapTotal:       8388604 kB
SwapFree:        8000000 kB
Shmem:            300000 kB
SReclaimable:     400000 kB
CommitLimit:    41306400 kB
HugePages_Total:       0
Hugepagesize:       2048 kB
`

// Host with one physical package of 2 cores, with 2 threads each.
const testHostCpuinfo = `processor	: 0
model name	: Test CPU
physical id	: 0
siblings	: 4
core id		: 0
cpu cores	: 2

processor	: 1
model name	: Test CPU
physical id	: 0
siblings	: 4
core id		: 0
cpu cores	: 2

processor	: 2
model name	: Test CPU
physical id	: 0
siblings	: 4
core id		: 1
cpu cores	: 2

processor	: 3
model name	: Test CPU
physical id	: 0
siblings	: 4
core id		: 1
cpu cores	: 2

`

// testFs returns a host file system where process testPid runs in a pod
// container cgroup, with the given cgroup files added.
func testFs(cgroupFiles map[string]string) fstest.MapFS {
	fsys := fstest.MapFS{
		"proc/meminfo":                  {Data: []byte(testHostMeminfo)},
		"proc/cpuinfo":                  {Data: []byte(testHostCpuinfo)},
		"proc/4242/cgroup":              {Data: []byte("0::" + testCntrCg + "\n")},
		"sys/devices/system/cpu/online": {Data: []byte(testHostCpus)},
	}
	for name, data := range cgroupFiles {
		fsys["sys/fs/cgroup"+name] = &fstest.MapFile{Data: []byte(data)}
	}
	return fsys
}

// readAll reads the whole content served by the handler, in chunks of the
// given size, the way the FUSE layer issues reads.
func readAll(t *testing.T, h domain.HandlerIface, fsys fstest.MapFS, chunk int) string {
	t.Helper()

	orig := hostFs
	hostFs = fsys
	t.Cleanup(func() { hostFs = orig })

	n := sysio.NewIOService(domain.IOMemFileService).NewIOnode("", h.GetPath(), 0)
	var out strings.Builder

	for {
		req := &domain.HandlerRequest{Pid: testPid, Offset: int64(out.Len()), Data: make([]byte, chunk)}
		sz, err := h.Read(n, req)
		if err == io.EOF {
			return out.String()
		}
		if err != nil {
			t.Fatalf("Read() failed: %v", err)
		}
		out.Write(req.Data[:sz])
	}
}

func meminfoLine(content, field string) string {
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, field+":") {
			return line
		}
	}
	return ""
}

func TestCpuList(t *testing.T) {
	for _, s := range []string{"0", "0-3", "0-3,8,10-11", "1,3,5"} {
		cpus, err := parseCpuList(s + "\n")
		if err != nil {
			t.Fatalf("parseCpuList(%q) failed: %v", s, err)
		}
		if got := formatCpuList(cpus); got != s {
			t.Errorf("formatCpuList(parseCpuList(%q)) = %q", s, got)
		}
	}

	if _, err := parseCpuList("0-x"); err == nil {
		t.Errorf("parseCpuList(\"0-x\") did not fail")
	}
}

func TestProcMeminfo_Read(t *testing.T) {
	memoryStat := strings.Join([]string{
		"anon 104857600",
		"file 52428800",
		"active_anon 94371840",
		"inactive_anon 10485760",
		"active_file 20971520",
		"inactive_file 31457280",
		"shmem 1048576",
		"slab_reclaimable 2097152",
	}, "\n")

	t.Run("container limit", func(t *testing.T) {
		got := readAll(t, ProcMeminfo_Handler, testFs(map[string]string{
			testPodCg + "/memory.max":           "2097152000",
			testCntrCg + "/memory.max":          "1048576000",
			testCntrCg + "/memory.current":      "209715200",
			testCntrCg + "/memory.stat":         memoryStat,
			testCntrCg + "/memory.swap.max":     "0",
			testCntrCg + "/memory.swap.current": "0",
		}), 4096)

		want := map[string]string{
			"MemTotal":       "MemTotal:        1024000 kB",
			"MemFree":        "MemFree:          819200 kB",
			"MemAvailable":   "MemAvailable:     849920 kB",
			"Buffers":        "Buffers:               0 kB",
			"Cached":         "Cached:            51200 kB",
			"Active":         "Active:           112640 kB",
			"Inactive(file)": "Inactive(file):    30720 kB",
			"Shmem":          "Shmem:              1024 kB",
			"SReclaimable":   "SReclaimable:       2048 kB",
			"SwapTotal":      "SwapTotal:             0 kB",
			"SwapFree":       "SwapFree:              0 kB",
			"CommitLimit":    "CommitLimit:    41306400 kB",
			"Hugepagesize":   "Hugepagesize:       2048 kB",
		}
		for field, line := range want {
			if got := meminfoLine(got, field); got != line {
				t.Errorf("%s line = %q, want %q", field, got, line)
			}
		}
		if !strings.HasSuffix(got, "HugePages_Total:       0\nHugepagesize:       2048 kB\n") {
			t.Errorf("unexpected trailing content:\n%s", got)
		}
	})

	t.Run("limit set by an ancestor", func(t *testing.T) {
		got := readAll(t, ProcMeminfo_Handler, testFs(map[string]string{
			testPodCg + "/memory.max":     "524288000",
			testPodCg + "/memory.current": "104857600",
			testCntrCg + "/memory.max":    "max",
		}), 4096)

		if line := meminfoLine(got, "MemTotal"); line != "MemTotal:         512000 kB" {
			t.Errorf("MemTotal line = %q", line)
		}
		if line := meminfoLine(got, "MemFree"); line != "MemFree:          409600 kB" {
			t.Errorf("MemFree line = %q", line)
		}
		if line := meminfoLine(got, "SwapTotal"); line != "SwapTotal:       8388604 kB" {
			t.Errorf("SwapTotal line = %q, want the host's swap when no swap limit is set", line)
		}
	})

	t.Run("no limit", func(t *testing.T) {
		got := readAll(t, ProcMeminfo_Handler, testFs(map[string]string{
			testCntrCg + "/memory.max": "max",
		}), 4096)

		if got != testHostMeminfo {
			t.Errorf("got:\n%s\nwant the host file", got)
		}
	})

	t.Run("limit above the host memory", func(t *testing.T) {
		got := readAll(t, ProcMeminfo_Handler, testFs(map[string]string{
			testCntrCg + "/memory.max": "137438953472",
		}), 4096)

		if got != testHostMeminfo {
			t.Errorf("got:\n%s\nwant the host file", got)
		}
	})
}

func TestProcCpuinfo_Read(t *testing.T) {
	tests := []struct {
		name         string
		files        map[string]string
		wantIds      []string
		wantSiblings string
		wantCores    string
	}{
		{"no limit", map[string]string{testCntrCg + "/cpu.max": "max 100000"}, []string{"0", "1", "2", "3"}, "4", "2"},
		{"fractional quota", map[string]string{testCntrCg + "/cpu.max": "50000 100000"}, []string{"0"}, "1", "1"},
		{"quota of two CPUs", map[string]string{testCntrCg + "/cpu.max": "200000 100000"}, []string{"0", "1"}, "2", "1"},
		{"tighter ancestor quota", map[string]string{
			testPodCg + "/cpu.max":  "100000 100000",
			testCntrCg + "/cpu.max": "300000 100000",
		}, []string{"0"}, "1", "1"},
		{"cpuset", map[string]string{testCntrCg + "/cpuset.cpus.effective": "2-3"}, []string{"2", "3"}, "2", "1"},
		{"cpuset and quota", map[string]string{
			testCntrCg + "/cpuset.cpus.effective": "1-3",
			testCntrCg + "/cpu.max":               "150000 100000",
		}, []string{"1", "2"}, "2", "2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Small chunks exercise reads at non-zero offsets.
			got := readAll(t, ProcCpuinfo_Handler, testFs(tt.files), 7)

			var ids []string
			for _, entry := range strings.Split(strings.TrimRight(got, "\n"), "\n\n") {
				ids = append(ids, cpuinfoField(entry, "processor"))
				if !strings.Contains(entry+"\n", "\nsiblings\t: "+tt.wantSiblings+"\n") {
					t.Errorf("entry siblings != %s:\n%s", tt.wantSiblings, entry)
				}
				if !strings.Contains(entry+"\n", "\ncpu cores\t: "+tt.wantCores+"\n") {
					t.Errorf("entry cpu cores != %s:\n%s", tt.wantCores, entry)
				}
			}
			if strings.Join(ids, ",") != strings.Join(tt.wantIds, ",") {
				t.Errorf("processors = %v, want %v", ids, tt.wantIds)
			}
			if !strings.HasSuffix(got, "\n\n") {
				t.Errorf("content does not end with a blank line: %q", got)
			}
		})
	}

	t.Run("format without processor entries", func(t *testing.T) {
		s390x := "vendor_id       : IBM/S390\n# processors    : 4\nprocessor 0: version = 00\n\n"
		fsys := testFs(map[string]string{testCntrCg + "/cpu.max": "50000 100000"})
		fsys["proc/cpuinfo"] = &fstest.MapFile{Data: []byte(s390x)}

		if got := readAll(t, ProcCpuinfo_Handler, fsys, 4096); got != s390x {
			t.Errorf("got %q, want the host file", got)
		}
	})
}

func TestSysDevicesSystemCpuOnline_Read(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"no limit", nil, "0-3\n"},
		{"fractional quota", map[string]string{testCntrCg + "/cpu.max": "50000 100000"}, "0\n"},
		{"cpuset", map[string]string{testCntrCg + "/cpuset.cpus.effective": "1,3"}, "1,3\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := readAll(t, SysDevicesSystemCpuOnline_Handler, testFs(tt.files), 4096); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}

	t.Run("reader outside cgroup v2", func(t *testing.T) {
		fsys := testFs(map[string]string{testCntrCg + "/cpu.max": "50000 100000"})
		fsys["proc/4242/cgroup"] = &fstest.MapFile{Data: []byte("4:memory:/docker/abc\n")}

		if got := readAll(t, SysDevicesSystemCpuOnline_Handler, fsys, 4096); got != testHostCpus {
			t.Errorf("got %q, want the host CPUs", got)
		}
	})
}
