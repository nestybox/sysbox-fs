// SPDX-License-Identifier: Apache-2.0

package implementations

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestProcCPUInfoWithInheritedQuota(t *testing.T) {
	mount := t.TempDir()
	parent := filepath.Join(mount, "task")
	reader := filepath.Join(parent, "agent")
	if err := os.MkdirAll(reader, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, "cpu.max"), []byte("150000 100000\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(reader, "cpu.max"), []byte("max 100000\n"), 0644); err != nil {
		t.Fatal(err)
	}
	allowed, err := parseCPUList("3,5-6")
	if err != nil || !reflect.DeepEqual(allowed, []uint64{3, 5, 6}) {
		t.Fatalf("CPU affinity = %v, %v", allowed, err)
	}
	n, err := quotaCPUCount(mount, "/task/agent", uint64(len(allowed)))
	if err != nil || n != 2 {
		t.Fatalf("CPU count = %d, %v, want 2", n, err)
	}
	data := "processor : 3\nphysical id : 5\nflags : first\n\nprocessor : 5\nflags : second\n\nprocessor : 6\nflags : third\n"
	got, err := formatProcCPUInfo(data, allowed[:n])
	want := "processor\t: 0\nflags : first\n\nprocessor\t: 1\nflags : second\n\n"
	if err != nil || got != want {
		t.Fatalf("cpuinfo = %q, %v, want %q", got, err, want)
	}
}

func TestProcDiskstatsCounters(t *testing.T) {
	devices := t.TempDir()
	if err := os.Symlink("../../devices/block/sda", filepath.Join(devices, "8:0")); err != nil {
		t.Fatal(err)
	}
	data := "8:0 rbytes=4096 wbytes=1024 rios=3 wios=2 dbytes=512 dios=1 cost.usage=2.5\n"
	got, err := formatProcDiskstats(data, devices)
	want := "8 0 sda 3 0 8 0 2 0 2 0 0 0 0 1 0 1 0 0 0"
	if fields := strings.Join(strings.Fields(got), " "); err != nil || fields != want {
		t.Fatalf("diskstats = %q, %v, want %q", fields, err, want)
	}
}

func TestProcStatCounters(t *testing.T) {
	got, err := formatProcStat("usage_usec 63000\nuser_usec 45000\nsystem_usec 18000\n", 1234)
	want := "cpu  4 0 1 0 0 0 0 0 0 0\nbtime 1234\n"
	if err != nil || got != want {
		t.Fatalf("stat = %q, %v, want %q", got, err, want)
	}
}
