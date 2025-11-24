//
// Copyright 2019-2025 Nestybox, Inc.
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
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
	"github.com/nestybox/sysbox-fs/mount"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// seccompNotifAddfd matches struct seccomp_notif_addfd from linux/seccomp.h
type seccompNotifAddfd struct {
	id          uint64
	flags       uint32
	srcfd       uint32
	newfd       uint32
	newfd_flags uint32
}

// RESOLVE_* flags for openat2 (from linux/openat2.h)
const (
	RESOLVE_NO_XDEV       = 0x01
	RESOLVE_NO_MAGICLINKS = 0x02
	RESOLVE_NO_SYMLINKS   = 0x04
	RESOLVE_BENEATH       = 0x08
	RESOLVE_IN_ROOT       = 0x10
	RESOLVE_CACHED        = 0x20
)

// openat2SyscallInfo holds the parsed arguments for openat2 syscall
type openat2SyscallInfo struct {
	syscallCtx           // syscall generic info
	dirfd      int32     // directory file descriptor
	path       string    // pathname to open
	flags      uint64    // open_how.flags
	mode       uint64    // open_how.mode
	resolve    uint64    // open_how.resolve
	notifyFd   int32     // seccomp notification file descriptor
	caps       [2]uint32 // effective capabilities of the process
}

// injectFd injects a file descriptor into the traced process using SECCOMP_IOCTL_NOTIF_ADDFD
// Returns the file descriptor number in the target process, or an error
func (si *openat2SyscallInfo) injectFd(srcfd int) (int, error) {

	addfd := seccompNotifAddfd{
		id:          si.reqId,
		flags:       0, // Let the kernel choose the fd number
		srcfd:       uint32(srcfd),
		newfd:       0, // 0 means kernel assigns lowest available fd
		newfd_flags: unix.O_CLOEXEC,
	}

	// Perform the SECCOMP_IOCTL_NOTIF_ADDFD ioctl
	targetFd, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(si.notifyFd),
		uintptr(unix.SECCOMP_IOCTL_NOTIF_ADDFD),
		uintptr(unsafe.Pointer(&addfd)),
	)

	if errno != 0 {
		return -1, errno
	}

	return int(targetFd), nil
}

// processOpenat2 handles the openat2 syscall processing
func (si *openat2SyscallInfo) processOpenat2() (*sysResponse, error) {
	var err error

	t := si.tracer
	fullPath := si.path

	// Per openat2(2): If path is absolute, then dirfd is ignored
	// (unless how.resolve contains RESOLVE_IN_ROOT, in which case
	// path is resolved relative to dirfd).
	isAbsolute := filepath.IsAbs(fullPath)
	resolveInRoot := (si.resolve & RESOLVE_IN_ROOT) != 0

	if !isAbsolute || (isAbsolute && resolveInRoot) {
		// Path needs to be resolved relative to dirfd or cwd
		if si.dirfd == unix.AT_FDCWD {
			// Path is relative to current working directory
			if !isAbsolute {
				fullPath = filepath.Join(si.cwd, fullPath)
			}
			// If absolute with RESOLVE_IN_ROOT, cwd is treated as root,
			// so absolute path is used as-is relative to cwd
		} else {
			// Path is relative to dirfd (or treated as relative if RESOLVE_IN_ROOT is set)
			dirPath, err := si.processInfo.GetFd(si.dirfd)
			if err != nil {
				// If we can't resolve dirfd, just continue with the syscall
				logrus.Debugf("openat2: pid: %d: failed to resolve dirfd %d: %v", si.pid, si.dirfd, err)
				return t.createContinueResponse(si.reqId), nil
			}

			if resolveInRoot && isAbsolute {
				// With RESOLVE_IN_ROOT, absolute paths are resolved relative to dirfd
				// by treating dirfd as the root. So "/foo/bar" becomes "dirfd/foo/bar"
				fullPath = filepath.Join(dirPath, strings.TrimPrefix(fullPath, "/"))
			} else {
				// Normal relative path resolution
				fullPath = filepath.Join(dirPath, fullPath)
			}
		}
	}

	fullPath = filepath.Clean(fullPath)

	fullPath, err = si.processInfo.ResolveProcSelf(fullPath)
	if err != nil {
		logrus.Debugf("openat2: pid: %d: failed to resolve /proc/self in path %s: %v", si.pid, si.path, err)
	}

	// Check if the path is under a sysbox-fs mount
	if mount.IsSysboxfsMount(fullPath) {
		logrus.Infof("openat2(): pid: %d: path under sysbox-fs mount detected: path = %s, flags = %#x, mode = %#x, resolve = %#x",
			si.pid, fullPath, si.flags, si.mode, si.resolve)

		// Drop some of the RESOLVE_* flags. These flags restrict path resolution in ways that don't work due
		// to sysbox-fs emulating some resources under /proc/sys/.
		cleanResolve := si.resolve &^ (RESOLVE_NO_XDEV | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH)
		cleanFlags := si.flags &^ unix.O_PATH

		// Open the file inside the container's namespaces via nsenter.
		payload := domain.Openat2SyscallPayload{
			Header: domain.NSenterMsgHeader{
				Root:         si.root,
				Cwd:          si.cwd,
				Capabilities: si.caps,
			},
			Path:             fullPath,
			Flags:            cleanFlags,
			Mode:             si.mode,
			Resolve:          cleanResolve,
			CheckForSysboxfs: true, // ensure the openat2 is opening a sysbox-fs managed file
		}

		nss := t.service.nss
		event := nss.NewEvent(
			si.pid,
			si.uid,
			si.gid,
			&domain.AllNSs,
			0,
			&domain.NSenterMessage{
				Type:    domain.Openat2SyscallRequest,
				Payload: payload,
			},
			nil,
			false,
		)

		// Launch nsenter-event
		err := nss.SendRequestEvent(event)
		if err != nil {
			return nil, err
		}

		// Obtain nsenter-event response
		responseMsg := nss.ReceiveResponseEvent(event)
		if responseMsg.Type == domain.ErrorResponse {
			resp := t.createErrorResponse(
				si.reqId,
				responseMsg.Payload.(fuse.IOerror).Code)
			return resp, nil
		}

		// Extract the opened file descriptor from the response (passed to sysbox-fs via SCM_RIGHTS by the nsenter process)
		respPayload := responseMsg.Payload.(domain.Openat2RespPayload)
		fd := respPayload.Fd

		logrus.Infof("openat2(): pid %d: received fd %d from nsenter for path %s", si.pid, fd, fullPath)

		// Inject the file descriptor into the traced process using SECCOMP_IOCTL_NOTIF_ADDFD
		targetFd, err := si.injectFd(fd)

		// Close the fd in sysbox-fs after injecting it (the target process now has a copy)
		unix.Close(fd)

		if err != nil {
			logrus.Errorf("openat2(): pid %d: failed to inject fd %d into target process %d: %v", si.pid, fd, si.pid, err)
			resp := t.createErrorResponse(si.reqId, syscall.EINVAL)
			return resp, nil
		}

		logrus.Infof("openat2(): pid %d: injected fd %d as %d for path %s", si.pid, fd, targetFd, fullPath)

		// Return success response with the target fd as the return value
		return t.createSuccessResponseWithRetValue(si.reqId, uint64(targetFd)), nil
	}

	// Otherwise let the kernel handle it
	return t.createContinueResponse(si.reqId), nil
}
