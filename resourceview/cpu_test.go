// SPDX-License-Identifier: Apache-2.0

package resourceview

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestQuotaCPUCount(t *testing.T) {
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
}
