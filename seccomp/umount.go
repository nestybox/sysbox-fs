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

	mip, err := mts.NewMountInfoParser(u.cntr, u.pid, false)
	if err != nil {
		return nil, err
	}

	if ok, resp := u.processUmountAllowed(mip); ok == false {
		return resp, nil
	}

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
		// /sys mounts from those that are present within 'chroot'ed contexts. In
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

	// Not a mount we manage, have the kernel do the unmount.
	return u.tracer.createContinueResponse(u.reqId), nil
}

// processUmmountAllowed purpose is to prevent immutable resources from being
// unmounted.
//
// Method will return 'true' if the umount operation is deemed legit, and will
// return 'false' otherwise.
func (u *umountSyscallInfo) processUmountAllowed(
	mip domain.MountInfoParserIface) (bool, *sysResponse) {

	// There must be mountinfo state present for this target. Otherwise, let
	// kernel handle the error.
	info := mip.GetInfo(u.Target)
	if info == nil {
		return true, u.tracer.createContinueResponse(u.reqId)
	}

	// Return 'eperm' if the umount operation is over an immutable mountpoint.
	if u.cntr.IsImmutableMountID(info.MountID) {
		return false, u.tracer.createErrorResponse(u.reqId, syscall.EPERM)
	}

	// At this point we have already concluded that the mountpoint being
	// unmounted doesn't match any of the immutable resources, so we could
	// be tempted to allow all umount instructions reaching this stage to
	// succeed. However, there is one particular case that we must identify
	// to prevent the exposure of immutable masked resources. This is the case
	// of an umount instruction launched from an unshare() context that targets
	// an immutable resource. The rest of the code in this function deals with
	// the identification and handling of this particular case.

	p := u.processData

	// Allow umount if this one is launched from a process whose root-inode
	// differs from the sys container's initPid one.
	if p.RootInode() != u.cntr.InitProc().RootInode() {
		return true, u.tracer.createContinueResponse(u.reqId)
	}

	// Allow umount if this one is launched from a process' whose mount-ns
	// matches the sys container's one.
	processMountNs, err := p.MountNsInode()
	if err != nil {
		return true, nil
	}
	initProcMountNs, err := u.cntr.InitProc().MountNsInode()
	if err != nil {
		return true, nil
	}
	if processMountNs == initProcMountNs {
		return true, nil
	}

	// Allow umount if the targeted mountpoint is a recursive bind-mount.
	if mip.IsRecursiveBindMount(info) {
		return true, nil
	}

	// If not a recursive bindmount, treat entry like any other mountinfo entry:
	// check if it matches an immutable resource and prevent umount if that's
	// the case.
	if u.cntr.IsImmutableMountpoint(info.MountPoint) {
		return false, u.tracer.createErrorResponse(u.reqId, syscall.EPERM)
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

	// Adjust payload attributes attending to the process' root path. This is
	// needed to properly handle umount instructions generated within chroot
	// jail environments.
	if u.syscallCtx.root != "/" {
		for i := 0; i < len(payload); i++ {
			payload[i].Target = filepath.Join(u.syscallCtx.root, payload[i].Target)
		}
	}

	return &payload
}

func (u *umountSyscallInfo) String() string {
	return fmt.Sprintf("target: %s, flags: %#x, root: %s, cwd: %s",
		u.Target, u.Flags, u.root, u.cwd)
}
