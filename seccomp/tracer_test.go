//
// Copyright 2019-2020 Nestybox, Inc.
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

package seccomp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"

	unixIpc "github.com/nestybox/sysbox-ipc/unix"
	libseccomp "github.com/seccomp/libseccomp-golang"
)

func Test_syscallTracer_createErrorResponse(t *testing.T) {
	type fields struct {
		sms      *SyscallMonitorService
		srv      *unixIpc.Server
		pollsrv  *unixIpc.PollServer
		syscalls map[seccompArchSyscallPair]string
	}

	var f1 = &fields{
		sms:      nil,
		srv:      nil,
		pollsrv:  nil,
		syscalls: nil,
	}

	// Expected results.

	var r1 = &sysResponse{
		ID:    0,
		Error: int32(syscall.EPERM),
		Val:   0,
		Flags: 0,
	}
	var r2 = &sysResponse{
		ID:    1,
		Error: int32(syscall.EINVAL),
		Val:   0,
		Flags: 0,
	}

	type args struct {
		id  uint64
		err error
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *sysResponse
	}{
		// A received syscall.Errno error must be honored (no modifications allowed).
		{"1", *f1, args{0, syscall.EPERM}, r1},

		// Verify that "errorString" errors are properly type-asserted.
		{"2", *f1, args{1, fmt.Errorf("testing errorString error type 1")}, r2},

		// Same as above but with another error constructor.
		{"3", *f1, args{1, errors.New("testing errorString error type 2")}, r2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracer := &syscallTracer{
				service:  tt.fields.sms,
				srv:      tt.fields.srv,
				pollsrv:  tt.fields.pollsrv,
				syscalls: tt.fields.syscalls,
			}
			if got := tracer.createErrorResponse(tt.args.id, tt.args.err); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("syscallTracer.createErrorResponse() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSysinfoLayout(t *testing.T) {
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

func TestSchedGetaffinityLayout(t *testing.T) {
	mask, err := encodeAffinity([]uint64{2, 71}, 128, 8)
	if err != nil || len(mask) != 16 ||
		binary.NativeEndian.Uint64(mask) != 4 || binary.NativeEndian.Uint64(mask[8:]) != 128 {
		t.Fatalf("invalid affinity mask: %x, %v", mask, err)
	}
	if _, err := encodeAffinity([]uint64{71}, 8, 8); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("short mask returned %v, want EINVAL", err)
	}
}

func TestWritableProcRange(t *testing.T) {
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
		if got := writableProcRange(strings.NewReader(mappings), tc.start, tc.end); got != tc.writable {
			t.Errorf("writableProcRange(%x, %x) = %t, want %t", tc.start, tc.end, got, tc.writable)
		}
	}
}

func TestSyscallNotificationArchitectures(t *testing.T) {
	for _, native := range []libseccomp.ScmpArch{libseccomp.ArchAMD64, libseccomp.ArchARM64} {
		compat := libseccomp.ArchX86
		if native == libseccomp.ArchARM64 {
			compat = libseccomp.ArchARM
		}
		supported := getSupportedCompatibleSyscalls(native)
		for arch, wordSize := range map[libseccomp.ScmpArch]int{native: 8, compat: 4} {
			if got := syscallWordSize(arch); got != wordSize {
				t.Errorf("%s word size = %d, want %d", arch, got, wordSize)
			}
			for _, name := range []string{"sysinfo", "sched_getaffinity"} {
				if !slices.Contains(supported[arch], name) {
					t.Errorf("%s handler missing for %s", name, arch)
				}
				number, err := libseccomp.GetSyscallFromNameByArch(name, arch)
				if err != nil || number < 0 {
					t.Errorf("%s syscall number for %s = %d, %v", name, arch, number, err)
				}
			}
		}
	}
}
