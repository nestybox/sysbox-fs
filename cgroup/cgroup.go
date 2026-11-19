// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const Mount = "/sys/fs/cgroup"

// Scope resolves host process IDs and checks that the caller belongs to the
// registered Sysbox container's cgroup subtree.
func Scope(pid, initPid uint32) (string, string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", "", err
	}
	return ScopeFromCgroup(data, initPid)
}

// ScopeFromCgroup also accepts data read through a pinned proc directory.
func ScopeFromCgroup(data []byte, initPid uint32) (string, string, error) {
	reader, err := CgroupPath(data)
	if err != nil {
		return "", "", err
	}
	container, err := unifiedCgroup(initPid)
	if err != nil {
		return "", "", err
	}
	// Sysbox starts its init process in a leaf under the container cgroup.
	container = strings.TrimSuffix(container, "/init.scope")
	if container == "" || container == "/" ||
		(reader != container && !strings.HasPrefix(reader, container+"/")) {
		return "", "", syscall.EACCES
	}

	return reader, container, nil
}

func unifiedCgroup(pid uint32) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}
	return CgroupPath(data)
}

// CgroupPath extracts the unified hierarchy path from a task's cgroup file.
func CgroupPath(data []byte) (string, error) {
	for line := range strings.SplitSeq(string(data), "\n") {
		if path, ok := strings.CutPrefix(line, "0::"); ok && filepath.IsAbs(path) && filepath.Clean(path) == path {
			return path, nil
		}
	}
	return "", syscall.ENOTSUP
}
