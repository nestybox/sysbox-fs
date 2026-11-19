// SPDX-License-Identifier: Apache-2.0

package seccomp

import (
	"encoding/binary"
	"errors"
	"strings"
	"syscall"
	"testing"
)

func TestResourceSysinfoLayout(t *testing.T) {
	const total = 6 << 30
	const free = 5 << 30
	native, err := encodeSysinfo(8, 7, total, free, 9)
	if err != nil || len(native) != 112 ||
		binary.NativeEndian.Uint64(native[32:]) != total ||
		binary.NativeEndian.Uint64(native[40:]) != free ||
		binary.NativeEndian.Uint16(native[80:]) != 9 ||
		binary.NativeEndian.Uint32(native[104:]) != 1 {
		t.Fatalf("invalid native sysinfo result: %x, %v", native, err)
	}
	compat, err := encodeSysinfo(4, 7, total, free, 9)
	if err != nil || len(compat) != 64 {
		t.Fatalf("invalid compat sysinfo result: %x, %v", compat, err)
	}
	unit := uint64(binary.NativeEndian.Uint32(compat[52:]))
	if uint64(binary.NativeEndian.Uint32(compat[16:]))*unit != total ||
		uint64(binary.NativeEndian.Uint32(compat[20:]))*unit != free ||
		binary.NativeEndian.Uint16(compat[40:]) != 9 {
		t.Fatalf("invalid compat sysinfo fields: %x", compat)
	}
}

func TestResourceAffinityLayout(t *testing.T) {
	mask, err := encodeAffinity([]uint64{2, 71}, 128, 8)
	if err != nil || len(mask) != 16 ||
		binary.NativeEndian.Uint64(mask) != 4 || binary.NativeEndian.Uint64(mask[8:]) != 128 {
		t.Fatalf("invalid affinity mask: %x, %v", mask, err)
	}
	if _, err := encodeAffinity([]uint64{71}, 8, 8); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("short mask returned %v, want EINVAL", err)
	}
}

func TestWritableResourceRange(t *testing.T) {
	const mappings = "1000-2000 r--p\n2000-3000 rw-p\n3000-4000 rw-p\n5000-6000 rw-p\n"
	for _, tc := range []struct {
		start, end uint64
		writable   bool
	}{
		{0x2000, 0x2001, true},
		{0x2ff0, 0x3010, true},
		{0x1ff0, 0x2010, false},
		{0x3ff0, 0x5010, false},
	} {
		if got := writableResourceRange(strings.NewReader(mappings), tc.start, tc.end); got != tc.writable {
			t.Errorf("writableResourceRange(%x, %x) = %t, want %t", tc.start, tc.end, got, tc.writable)
		}
	}
}
