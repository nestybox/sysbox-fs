// SPDX-License-Identifier: Apache-2.0

package seccomp

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/nestybox/sysbox-fs/resourceview"
	"golang.org/x/sys/unix"
)

func scopedAffinity(task int, reader string, targetPID int32, length uint32, wordSize int) ([]byte, error) {
	if length == 0 || length%uint32(wordSize) != 0 {
		return nil, syscall.EINVAL
	}
	status, err := affinityTargetStatus(task, reader, targetPID)
	if err != nil {
		return nil, err
	}
	cpus, err := resourceview.CPUs(status, reader)
	if err != nil {
		return nil, err
	}
	return encodeAffinity(cpus, length, wordSize)
}

func encodeAffinity(cpus []uint64, length uint32, wordSize int) ([]byte, error) {
	// Linux's raw syscall returns the number of bytes copied, in whole
	// ABI words. Use real CPU IDs so applications can still pin to them.
	bitsPerWord := uint64(8 * wordSize)
	size := (cpus[len(cpus)-1]/bitsPerWord + 1) * uint64(wordSize)
	if size > uint64(length) {
		return nil, syscall.EINVAL
	}
	mask := make([]byte, size)
	for _, cpu := range cpus {
		word := mask[cpu/bitsPerWord*uint64(wordSize):]
		bit := uint64(1) << (cpu % bitsPerWord)
		if wordSize == 4 {
			binary.NativeEndian.PutUint32(word, binary.NativeEndian.Uint32(word)|uint32(bit))
		} else {
			binary.NativeEndian.PutUint64(word, binary.NativeEndian.Uint64(word)|bit)
		}
	}
	return mask, nil
}

func affinityTargetStatus(task int, reader string, targetPID int32) ([]byte, error) {
	if targetPID < 0 {
		return nil, syscall.ESRCH
	}
	status, err := readResourceTaskFile(task, "status")
	if err != nil || targetPID == 0 || namespacePID(status) == uint32(targetPID) {
		return status, err
	}
	// A positive PID is relative to the caller's PID namespace. Limit
	// lookups to threads in that namespace and the caller's own cgroup.
	var ns unix.Stat_t
	if err := unix.Fstatat(task, "ns/pid", &ns, 0); err != nil {
		return nil, err
	}
	threads, err := os.ReadFile(filepath.Join(resourceview.Mount, reader, "cgroup.threads"))
	if err != nil {
		return nil, err
	}
	for pidText := range strings.FieldsSeq(string(threads)) {
		pid, err := strconv.ParseUint(pidText, 10, 32)
		if err != nil {
			return nil, err
		}
		if status := matchingAffinityTarget(uint32(pid), uint32(targetPID), reader, ns); status != nil {
			return status, nil
		}
	}
	return nil, syscall.ESRCH
}

func matchingAffinityTarget(pid, targetPID uint32, reader string, ns unix.Stat_t) []byte {
	task, err := openResourceTask(pid)
	if err != nil {
		return nil
	}
	defer unix.Close(task)
	var targetNS unix.Stat_t
	if err := unix.Fstatat(task, "ns/pid", &targetNS, 0); err != nil ||
		targetNS.Dev != ns.Dev || targetNS.Ino != ns.Ino {
		return nil
	}
	status, err := readResourceTaskFile(task, "status")
	if err != nil || namespacePID(status) != targetPID {
		return nil
	}
	cgroup, err := readResourceTaskFile(task, "cgroup")
	if err != nil {
		return nil
	}
	path, err := resourceview.CgroupPath(cgroup)
	if err != nil || path != reader {
		return nil
	}
	return status
}

func namespacePID(status []byte) uint32 {
	for line := range strings.SplitSeq(string(status), "\n") {
		if values, ok := strings.CutPrefix(line, "NSpid:"); ok {
			pids := strings.Fields(values)
			if len(pids) > 0 {
				pid, _ := strconv.ParseUint(pids[len(pids)-1], 10, 32)
				return uint32(pid)
			}
		}
	}
	return 0
}
