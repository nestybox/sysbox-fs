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
	"errors"
	"syscall"

	"github.com/nestybox/sysbox-fs/cgroup"
	"github.com/nestybox/sysbox-fs/domain"
	libseccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

// Syscall generic information / state.
type syscallCtx struct {
	syscallNum  int32                 // Value representing the syscall
	syscallName string                // Name of the syscall
	reqId       uint64                // Id associated to the syscall request
	pid         uint32                // Pid of the process generating the syscall
	uid         uint32                // Uid of the process generating the syscall
	gid         uint32                // Gid of the process generating the syscall
	cwd         string                // Cwd of process generating the syscall
	root        string                // Root of process generating the syscall
	processInfo domain.ProcessIface   // Process details associated to the syscall request
	cntr        domain.ContainerIface // Container hosting the process generating the syscall
	tracer      *syscallTracer        // Backpointer to the seccomp-tracer owning the syscall
}

func syscallErrno(err error) syscall.Errno {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return syscall.EIO
	}
	return errno
}

func syscallWordSize(arch libseccomp.ScmpArch) int {
	switch arch {
	case libseccomp.ArchAMD64, libseccomp.ArchARM64:
		return 8
	case libseccomp.ArchX86, libseccomp.ArchARM:
		return 4
	}
	return 0
}

// openScopedSyscallTask pins the caller's proc directory before validating the
// notification, so subsequent reads and writes cannot target a reused PID.
func openScopedSyscallTask(req *sysRequest, fd int32, initPid uint32) (int, string, string, error) {
	task, err := openProcTask(req.Pid)
	if err != nil {
		return -1, "", "", syscall.ESRCH
	}
	if err := libseccomp.NotifIDValid(libseccomp.ScmpFd(fd), req.ID); err != nil {
		unix.Close(task)
		return -1, "", "", err
	}
	membership, err := readProcTaskFile(task, "cgroup")
	if err != nil {
		unix.Close(task)
		return -1, "", "", err
	}
	reader, container, err := cgroup.ScopeFromCgroup(membership, initPid)
	if err != nil {
		unix.Close(task)
		return -1, "", "", err
	}
	return task, reader, container, nil
}
