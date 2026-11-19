// SPDX-License-Identifier: Apache-2.0

package seccomp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/resourceview"
	libseccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

func (t *syscallTracer) processResourceSyscall(req *sysRequest, fd int32, cntr domain.ContainerIface, name string) (*sysResponse, error) {
	wordSize := resourceWordSize(req.Data.Arch)
	if wordSize == 0 {
		return t.createErrorResponse(req.ID, syscall.ENOSYS), nil
	}
	task, err := openResourceTask(req.Pid)
	if err != nil {
		return t.createErrorResponse(req.ID, syscall.ESRCH), nil
	}
	defer unix.Close(task)

	// Validate after opening the proc directory, which pins the target even
	// if its numeric PID is later reused.
	if err := libseccomp.NotifIDValid(libseccomp.ScmpFd(fd), req.ID); err != nil {
		return nil, err
	}
	cgroup, err := readResourceTaskFile(task, "cgroup")
	if err != nil {
		return t.resourceError(req.ID, err), nil
	}
	reader, container, err := resourceview.ScopeFromCgroup(cgroup, cntr.InitPid())
	if err != nil {
		return t.resourceError(req.ID, err), nil
	}

	var data []byte
	addr := req.Data.Args[0]
	var returnValue uint64
	switch name {
	case "sysinfo":
		data, err = scopedSysinfo(reader, container, cntr.Ctime(), wordSize)
	case "sched_getaffinity":
		addr = req.Data.Args[2]
		data, err = scopedAffinity(task, reader, int32(req.Data.Args[0]), uint32(req.Data.Args[1]), wordSize)
		returnValue = uint64(len(data))
	}
	if err != nil {
		return t.resourceError(req.ID, err), nil
	}
	if err := writeResourceResult(task, fd, req.ID, addr, data); err != nil {
		return t.resourceError(req.ID, err), nil
	}
	return t.createSuccessResponseWithRetValue(req.ID, returnValue), nil
}

func (t *syscallTracer) resourceError(id uint64, err error) *sysResponse {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		errno = syscall.EIO
	}
	return t.createErrorResponse(id, errno)
}

func resourceWordSize(arch libseccomp.ScmpArch) int {
	switch arch {
	case libseccomp.ArchAMD64, libseccomp.ArchARM64:
		return 8
	case libseccomp.ArchX86, libseccomp.ArchARM:
		return 4
	}
	return 0
}

func scopedSysinfo(reader, container string, start time.Time, wordSize int) ([]byte, error) {
	total, free, err := resourceview.Memory(resourceview.Mount, reader, container)
	if err != nil {
		return nil, err
	}
	var procs uint64
	raw, err := os.ReadFile(filepath.Join(resourceview.Mount, reader, "pids.current"))
	if err == nil {
		procs, err = strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
		if err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	var elapsed int64
	if !start.IsZero() {
		elapsed = max(0, int64(time.Since(start)/time.Second))
	}
	return encodeSysinfo(wordSize, uint64(elapsed), total, free, uint16(min(procs, math.MaxUint16)))
}

func encodeSysinfo(wordSize int, uptime, total, free uint64, procs uint16) ([]byte, error) {
	size := 112
	unit := uint64(1)
	if wordSize == 4 {
		size = 64
		for total/unit > math.MaxUint32 {
			unit *= 2
		}
		if unit > math.MaxUint32 {
			return nil, syscall.EOVERFLOW
		}
	}
	// Match Linux struct sysinfo for both word sizes. Unavailable scoped
	// values (load, swap, shared, buffer and high memory) stay zero.
	data := make([]byte, size)
	putWord := func(index int, value uint64) {
		if wordSize == 4 {
			binary.NativeEndian.PutUint32(data[index*wordSize:], uint32(value))
		} else {
			binary.NativeEndian.PutUint64(data[index*wordSize:], value)
		}
	}
	putWord(0, uptime)
	putWord(4, total/unit)
	putWord(5, free/unit)
	binary.NativeEndian.PutUint16(data[10*wordSize:], procs)
	binary.NativeEndian.PutUint32(data[13*wordSize:], uint32(unit))
	return data, nil
}

func openResourceTask(pid uint32) (int, error) {
	return unix.Open(fmt.Sprintf("/proc/%d", pid), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
}
