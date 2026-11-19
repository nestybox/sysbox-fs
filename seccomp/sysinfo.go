// SPDX-License-Identifier: Apache-2.0

package seccomp

import (
	"encoding/binary"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/nestybox/sysbox-fs/cgroup"
	"github.com/nestybox/sysbox-fs/domain"
	"golang.org/x/sys/unix"
)

func (t *syscallTracer) processSysinfo(req *sysRequest, fd int32, cntr domain.ContainerIface) (*sysResponse, error) {
	wordSize := syscallWordSize(req.Data.Arch)
	if wordSize == 0 {
		return t.createErrorResponse(req.ID, syscall.ENOSYS), nil
	}
	task, reader, container, err := openScopedSyscallTask(req, fd, cntr.InitPid())
	if err != nil {
		return t.createErrorResponse(req.ID, syscallErrno(err)), nil
	}
	defer unix.Close(task)

	data, err := scopedSysinfo(reader, container, cntr.Ctime(), wordSize)
	if err != nil {
		return t.createErrorResponse(req.ID, syscallErrno(err)), nil
	}
	if err := writeSyscallResult(task, fd, req.ID, req.Data.Args[0], data); err != nil {
		return t.createErrorResponse(req.ID, syscallErrno(err)), nil
	}
	return t.createSuccessResponse(req.ID), nil
}

func scopedSysinfo(reader, container string, start time.Time, wordSize int) ([]byte, error) {
	total, free, err := cgroup.Memory(cgroup.Mount, reader, container)
	if err != nil {
		return nil, err
	}
	var procs uint64
	raw, err := os.ReadFile(filepath.Join(cgroup.Mount, reader, "pids.current"))
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
