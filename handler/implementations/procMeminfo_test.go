// SPDX-License-Identifier: Apache-2.0

package implementations

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCgroupMemorySharedLimit(t *testing.T) {
	const reader = "/shared/task/agent"
	const container = "/shared/task"
	mount := t.TempDir()
	if err := os.MkdirAll(filepath.Join(mount, reader), 0755); err != nil {
		t.Fatal(err)
	}
	for path, value := range map[string]string{
		"shared/memory.max":            "1024\n",
		"shared/memory.current":        "900\n",
		"shared/task/memory.max":       "max\n",
		"shared/task/memory.current":   "400\n",
		"shared/task/agent/memory.max": "max\n",
	} {
		if err := os.WriteFile(filepath.Join(mount, path), []byte(value), 0644); err != nil {
			t.Fatal(err)
		}
	}
	limit, available, err := cgroupMemory(mount, reader, container)
	if err != nil || limit != 1024 || available != 624 {
		t.Fatalf("cgroupMemory = (%d, %d, %v), want (1024, 624, nil)", limit, available, err)
	}
	if err := os.WriteFile(filepath.Join(mount, reader, "memory.max"), []byte("256\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mount, reader, "memory.current"), []byte("64\n"), 0644); err != nil {
		t.Fatal(err)
	}
	limit, available, err = cgroupMemory(mount, reader, container)
	if err != nil || limit != 256 || available != 192 {
		t.Fatalf("cgroupMemory = (%d, %d, %v), want (256, 192, nil)", limit, available, err)
	}
}
