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
	"fmt"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
	"github.com/sirupsen/logrus"
)

type umountSyscallInfo struct {
	syscallCtx                   // syscall generic info
	*domain.UmountSyscallPayload // unmount-syscall specific details
}

// MountSyscall processing wrapper instruction.
func (u *umountSyscallInfo) process() (*sysResponse, error) {

	// A procfs mount inside the container is a combination of a base procfs
	// mount plus sysbox-fs submounts, and we want the procfs mount to act as
	// one whole rather than a collection of mounts (i.e., just like a regular
	// procfs mount on a host). Thus, unmounts that occur on the base procfs
	// mount are accepted (we unmount the submounts first and then the base
	// mount). On the other hand, unmounts that target only the sysbox-fs
	// submounts are ignored. The reason we ignore them as opposed to returning
	// an error message is that we also ignore bind-to-self mounts on submounts
	// (see handling of bind-to-self submounts in mount.go); thus, returning an
	// error message would cause the sequence "mount --bind submount submount
	// && umount submount" to fail on the second command.
	//
	// Same applies to sysfs mounts.

	mts := u.tracer.service.mts
	if mts == nil {
		return nil, fmt.Errorf("unexpected mount-service handler")
	}

	mip, err := mts.NewMountInfoParser(u.cntr, u.processInfo, true, true, false)
	if err != nil {
		return nil, err
	}

	// Adjust umount target attribute attending to the process' root path.
	u.targetAdjust()

	if mip.IsSysboxfsBaseMount(u.Target) {

		// Special case: disallow unmounting of /proc; we must do this because we
		// use /proc as the source of other procfs mounts within the container
		// (i.e., if a new procfs is mounted at /some/path/inside/container/proc,
		// we bind-mount /proc/uptime to /some/path/inside/container/proc/uptime).
		// This restriction should be fine because unmounting /proc inside the
		// container is not a useful thing to do anyways. Same rationale applies
		// to "/sys".
		//
		// Also, notice that we want to clearly differentiate the root /proc and
		// /sys mounts from those that are present within chroot'ed contexts. In
		// the later case we want to allow users to mount (and umount) both /proc
		// and /sys file-systems.
		if (u.Target == "/proc" || u.Target == "/sys") && (u.syscallCtx.root == "/") {
			resp := u.tracer.createErrorResponse(u.reqId, syscall.EBUSY)
			return resp, nil
		}

		// If under the base mount there are any submounts *not* managed by
		// sysbox-fs, fail the unmount with EBUSY (such submounts must be
		// explicitly unmounted prior to unmounting the base mount).
		if mip.HasNonSysboxfsSubmount(u.Target) {
			resp := u.tracer.createErrorResponse(u.reqId, syscall.EBUSY)
			return resp, nil
		}

		// Process the unmount
		info := mip.GetInfo(u.Target)

		switch info.FsType {
		case "proc":
			// Sysbox-fs emulates all new procfs mounts inside the container by
			// mounting the kernel's procfs and the mounting sysbox-fs on
			// portions of procfs (e.g., proc/sys, proc/uptime, etc.)
			logrus.Debugf("Processing procfs unmount: %v", u)
			return u.processUmount(mip)

		case "sysfs":
			// For sysfs we do something similar to procfs.
			logrus.Debugf("Processing sysfs unmount: %v", u)
			return u.processUmount(mip)

		case "overlay":
			// Handle umounts of overlay fs.
			logrus.Debugf("Processing overlayfs unmount: %v", u)
			return u.processUmount(mip)
		}

		// Not a mount we manage, have the kernel do the unmount.
		return u.tracer.createContinueResponse(u.reqId), nil

	} else if mip.IsSysboxfsSubmount(u.Target) {
		logrus.Debugf("Ignoring unmount of sysbox-fs managed submount at %s",
			u.Target)
		return u.tracer.createSuccessResponse(u.reqId), nil
	}

	// Verify if the umount op is addressing an immutable resource and prevent
	// it if that's the case.
	if ok, resp := u.umountAllowed(mip); ok == false {
		return resp, nil
	}

	// Not a mount we manage, have the kernel do the unmount.
	return u.tracer.createContinueResponse(u.reqId), nil
}

// umountAllowed purpose is to prevent immutable resources from being
// unmounted.
//
// Method will return 'true' when the unmount operation is deemed legit, and
// will return 'false' otherwise.
func (u *umountSyscallInfo) umountAllowed(
	mip domain.MountInfoParserIface) (bool, *sysResponse) {

	// Skip file-systems explicitly handled by sysbox-fs.
	if u.FsType == "proc" || u.FsType == "sysfs" {
		return true, nil
	}

	// There must be mountinfo state present for this target. Otherwise, let
	// kernel handle the error.
	info := mip.GetInfo(u.Target)
	if info == nil {
		return false, u.tracer.createContinueResponse(u.reqId)
	}

	//
	// The following scenarios are relevant within the context of this function
	// and will be handled separately to ease the logic comprehension and its
	// maintenability / debuggability.
	//
	// The different columns in this table denote the 'context' in which the
	// unmount process is executing, and thereby, dictates the logic chosen
	// to handle each unmount request.
	//
	//    +-----------+--------------+--------------+----------+
	//    | Scenarios | Unshare(mnt) | Pivot-root() | Chroot() |
	//    +-----------+--------------+--------------+----------+
	//    | 1         | no           | no           | no       |
	//    | 2         | no           | yes          | no       |
	//    | 3         | no           | no           | yes      |
	//    | 4         | no           | yes          | yes      |
	//    | 5         | yes          | no           | no       |
	//    | 6         | yes          | yes          | no       |
	//    | 7         | yes          | no           | yes      |
	//    | 8         | yes          | yes          | yes      |
	//    +-----------+--------------+--------------+----------+
	//

	// Identify the mount-ns of the process launching the unmount to compare it
	// with the one of the sys container's initpid. In the unlikely case of an
	// error, let the kernel deal with it.
	processMountNs, err := u.processInfo.MountNsInode()
	if err != nil {
		return false, u.tracer.createErrorResponse(u.reqId, syscall.EINVAL)
	}
	initProcMountNs, err := u.cntr.InitProc().MountNsInode()
	if err != nil {
		return false, u.tracer.createErrorResponse(u.reqId, syscall.EINVAL)
	}

	// Obtain the sys-container's root-path inode.
	syscntrRootInode := u.cntr.InitProc().RootInode()

	// If process' mount-ns matches the sys-container's one, then we can simply
	// rely on the target's mountID to discern an immutable target from a
	// regular one. Otherwise, we cannot rely on the mountID field, as the values
	// allocated by kernel for these very mountpoints will differ in other mount
	// namespaces.
	if processMountNs == initProcMountNs {

		if ok := u.cntr.IsImmutableMountID(info.MountID); ok == true {

			if logrus.IsLevelEnabled(logrus.DebugLevel) {
				if u.processInfo.Root() == "/" {
					processRootInode := u.processInfo.RootInode()

					if processRootInode == syscntrRootInode {
						// Scenario 1): no-unshare(mnt) & no-pivot() & no-chroot()
						logrus.Debugf("Rejected unmount operation on immutable target %s (scenario 1)",
							u.Target)
					} else {
						// Scenario 2): no-unshare(mnt) & pivot() & no-chroot()
						logrus.Debugf("Rejected unmount operation on immutable target %s (scenario 2)",
							u.Target)
					}

				} else {
					// We are dealing with a chroot'ed process, so obtain the inode of "/"
					// as seen within the process' namespaces, and *not* the one associated
					// to the process' root-path.
					processRootInode, err := mip.ExtractInode("/")
					if err != nil {
						return false, u.tracer.createErrorResponse(u.reqId, syscall.EINVAL)
					}

					if processRootInode == syscntrRootInode {
						// Scenario 3: no-unshare(mnt) & no-pivot() & chroot()
						logrus.Debugf("Rejected unmount operation on immutable target %s (scenario 3)",
							u.Target)
					} else {
						// Scenario 4: no-unshare(mnt) & pivot() & chroot()
						logrus.Debugf("Rejected unmount operation on immutable target %s (scenario 4)",
							u.Target)
					}
				}
			}

			return false, u.tracer.createErrorResponse(u.reqId, syscall.EPERM)
		}

		return true, nil

	} else {

		if u.processInfo.Root() == "/" {
			processRootInode := u.processInfo.RootInode()

			// Scenario 5): unshare(mnt) & no-pivot() & no-chroot()
			if processRootInode == syscntrRootInode {
				// We need to check if we're dealing with an overlapped mount, as
				// this is a case that we usually (see exception below) want to
				// allow.
				if mip.IsOverlapMount(info) {
					// The exception mentioned above refer to the scenario where
					// the overlapped mountpoint is an immutable itself, hence the
					// checkpoint below.
					if u.cntr.IsImmutableOverlapMountpoint(info.MountPoint) {
						logrus.Debugf("Rejected unmount operation on immutable overlapped target %s (scenario 5)",
							u.Target)
						return false, u.tracer.createErrorResponse(u.reqId, syscall.EPERM)
					}
					return true, nil
				}

				// In this scenario we have full access to all the mountpoints
				// within the sys-container (different mount-id though), so we
				// can safely rely on their mountinfo attributes to determine
				// resource's immutability.
				if u.cntr.IsImmutableMountpoint(info.MountPoint) {
					logrus.Debugf("Rejected unmount operation on immutable target %s (scenario 5)",
						u.Target)
					return false, u.tracer.createErrorResponse(u.reqId, syscall.EPERM)
				}

				return true, nil
			}

			// Scenario 6): unshare(mnt) & pivot() & no-chroot()
			if processRootInode != syscntrRootInode {
				if mip.IsOverlapMount(info) {
					return true, nil
				}

				if u.cntr.IsImmutableMount(info) {
					logrus.Debugf("Rejected unmount operation on immutable target %s (scenario 6)",
						u.Target)
					return false, u.tracer.createErrorResponse(u.reqId, syscall.EPERM)
				}
				return true, nil
			}

			return true, nil
		}

		if u.processInfo.Root() != "/" {
			// We are dealing with a chroot'ed process, so obtain the inode of "/"
			// as seen within the process' namespaces, and *not* the one associated
			// to the process' root-path.
			processRootInode, err := mip.ExtractInode("/")
			if err != nil {
				return false, u.tracer.createErrorResponse(u.reqId, syscall.EINVAL)
			}

			// Scenario 7): unshare(mnt) & no-pivot() & chroot()
			if processRootInode == syscntrRootInode {
				// We need to check if we're dealing with an overlapped mount, as
				// this is a case that we usually (see exception below) want to
				// allow.
				if mip.IsOverlapMount(info) {
					// The exception mentioned above refer to the scenario where
					// the overlapped mountpoint is an immutable itself, hence the
					// checkpoint below.
					if u.cntr.IsImmutableOverlapMountpoint(info.MountPoint) {
						logrus.Debugf("Rejected unmount operation on immutable overlapped target %s (scenario 7)",
							u.Target)
						return false, u.tracer.createErrorResponse(u.reqId, syscall.EPERM)
					}
					return true, nil
				}

				// In this scenario we have full access to all the mountpoints
				// within the sys-container (different mount-id though), so we
				// can safely rely on their mountinfo attributes to determine
				// resource's immutability.
				if u.cntr.IsImmutableMountpoint(info.MountPoint) {
					logrus.Debugf("Rejected unmount operation on immutable target %s (scenario 7)",
						u.Target)
					return false, u.tracer.createErrorResponse(u.reqId, syscall.EPERM)
				}

				return true, nil
			}

			// Scenario 8): unshare(mnt) & pivot() & chroot()
			if processRootInode != syscntrRootInode {
				if mip.IsOverlapMount(info) {
					if u.cntr.IsImmutableMount(info) {
						logrus.Debugf("Rejected unmount operation on immutable overlapped target %s (scenario 8)",
							u.Target)
						return false, u.tracer.createErrorResponse(u.reqId, syscall.EPERM)
					}
					return true, nil
				}

				if u.cntr.IsImmutableMount(info) {
					logrus.Debugf("Rejected unmount operation on immutable target %s (scenario 8)",
						u.Target)
					return false, u.tracer.createErrorResponse(u.reqId, syscall.EPERM)
				}

				return true, nil
			}
		}
	}

	return true, nil
}

// Method handles umount syscall requests on sysbox-fs managed base mounts.
func (u *umountSyscallInfo) processUmount(
	mip domain.MountInfoParserIface) (*sysResponse, error) {

	// Create instructions payload.
	payload := u.createUmountPayload(mip)

	// Create nsenter-event envelope.
	nss := u.tracer.service.nss
	event := nss.NewEvent(
		u.syscallCtx.pid,
		&domain.AllNSs,
		&domain.NSenterMessage{
			Type:    domain.UmountSyscallRequest,
			Payload: payload,
		},
		nil,
		false,
	)

	// Launch nsenter-event.
	err := nss.SendRequestEvent(event)
	if err != nil {
		return nil, err
	}

	// Obtain nsenter-event response.
	responseMsg := nss.ReceiveResponseEvent(event)
	if responseMsg.Type == domain.ErrorResponse {
		resp := u.tracer.createErrorResponse(
			u.reqId,
			responseMsg.Payload.(fuse.IOerror).Code)

		return resp, nil
	}

	return u.tracer.createSuccessResponse(u.reqId), nil
}

// Build instructions payload required to unmount a sysbox-fs base mount (and
// any submounts under it)
func (u *umountSyscallInfo) createUmountPayload(
	mip domain.MountInfoParserIface) *[]*domain.UmountSyscallPayload {

	var payload []*domain.UmountSyscallPayload

	submounts := []string{}

	if mip.IsSysboxfsBaseMount(u.Target) {
		submounts = mip.GetSysboxfsSubMounts(u.Target)
	} else {
		submounts = append(submounts, u.Target)
	}

	for _, subm := range submounts {
		info := mip.GetInfo(subm)
		newelem := &domain.UmountSyscallPayload{
			domain.NSenterMsgHeader{},
			domain.Mount{
				Target: info.MountPoint,
				Flags:  u.Flags,
			},
		}
		payload = append(payload, newelem)
	}

	if mip.IsSysboxfsBaseMount(u.Target) {
		payload = append(payload, u.UmountSyscallPayload)
	}

	return &payload
}

// Method addresses scenarios where the process generating the umount syscall has
// a 'root' attribute different than default one ("/"). This is typically the
// case in chroot'ed environments. Method's goal is to make the required target
// adjustments so that sysbox-fs can carry out the mount in the expected context.
func (u *umountSyscallInfo) targetAdjust() {

	root := u.syscallCtx.root

	if root == "/" {
		return
	}

	u.Target = filepath.Join(root, u.Target)
}

// Undo targetAdjust().
func (u *umountSyscallInfo) targetUnadjust() {

	root := u.syscallCtx.root

	if root == "/" {
		return
	}

	u.Target = strings.TrimPrefix(u.Target, u.root)
}

func (u *umountSyscallInfo) String() string {
	return fmt.Sprintf("target: %s, flags: %#x, root: %s, cwd: %s",
		u.Target, u.Flags, u.root, u.cwd)
}
