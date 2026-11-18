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

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
	"github.com/nestybox/sysbox-fs/mount"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

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
			ReqId:            si.reqId,
			NotifyFd:         si.notifyFd,
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

		// The nsenter agent opened the file and injected it into the traced
		// process itself (SECCOMP_IOCTL_NOTIF_ADDFD), so sysbox-fs never holds
		// an fd into its own FUSE mounts. Holding one would let a concurrent
		// fork of an nsenter process (whose child closes inherited fds in
		// dup3) block in fuse_flush on an inode lock owned by a writer that is
		// waiting on sysbox-fs itself, deadlocking sysbox-fs.
		targetFd := responseMsg.Payload.(domain.Openat2RespPayload).Fd

		logrus.Infof("openat2(): pid %d: nsenter injected fd %d for path %s", si.pid, targetFd, fullPath)

		// Return success response with the target fd as the return value
		return t.createSuccessResponseWithRetValue(si.reqId, uint64(targetFd)), nil
	}

	// Otherwise let the kernel handle it
	return t.createContinueResponse(si.reqId), nil
}
