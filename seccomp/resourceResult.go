// SPDX-License-Identifier: Apache-2.0

package seccomp

import (
	"bufio"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"syscall"

	libseccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

func readResourceTaskFile(task int, name string) ([]byte, error) {
	fd, err := unix.Openat(task, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	return io.ReadAll(file)
}

func writeResourceResult(task int, listener int32, id, addr uint64, data []byte) error {
	if addr == 0 || addr > math.MaxInt64-uint64(len(data)) {
		return syscall.EFAULT
	}
	// Open through the already pinned proc task directory. The mem fd
	// refers to that task's address space, even if the PID is reused.
	mem, err := unix.Openat(task, "mem", unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return syscall.EFAULT
	}
	defer unix.Close(mem)
	// proc mem can force writes even to read-only pages. Check the
	// current mappings before using it for a copy_to_user-style result.
	maps, err := unix.Openat(task, "maps", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return syscall.EFAULT
	}
	file := os.NewFile(uintptr(maps), "maps")
	defer file.Close()
	if !writableResourceRange(file, addr, addr+uint64(len(data))) {
		return syscall.EFAULT
	}
	if err := libseccomp.NotifIDValid(libseccomp.ScmpFd(listener), id); err != nil {
		return err
	}
	n, err := unix.Pwrite(mem, data, int64(addr))
	if err != nil || n != len(data) {
		return syscall.EFAULT
	}
	return nil
}

func writableResourceRange(maps io.Reader, start, end uint64) bool {
	lines := bufio.NewScanner(maps)
	for lines.Scan() {
		fields := strings.Fields(lines.Text())
		if len(fields) < 2 {
			return false
		}
		lo, hi, _ := strings.Cut(fields[0], "-")
		mapEnd, err := strconv.ParseUint(hi, 16, 64)
		if err != nil {
			return false
		}
		if mapEnd <= start {
			continue
		}
		mapStart, err := strconv.ParseUint(lo, 16, 64)
		if err != nil || mapStart > start || len(fields[1]) < 2 || fields[1][1] != 'w' {
			return false
		}
		if mapEnd >= end {
			return true
		}
		start = mapEnd
	}
	return false
}
