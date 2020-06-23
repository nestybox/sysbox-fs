//
// Copyright: (C) 2020 Nestybox Inc.  All rights reserved.
//

package seccomp

import (
	"fmt"
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

	mh := u.tracer.mountHelper

	mip, err := NewMountInfoParser(mh, u.cntr, u.pid, false)
	if err != nil {
		return nil, err
	}

	if mip.IsSysboxfsBaseMount(u.Target) {

		// Special case: disallow unmounting of /proc; we must do this because we
		// use /proc as the source of other procfs mounts within the container
		// (i.e., if a new procfs is mounted at /some/path/inside/container/proc,
		// we bind-mount /proc/uptime to /some/path/inside/container/proc/uptime).
		// This restriction should be fine because unmounting /proc inside the
		// container is not a useful thing to do anyways. Same rationale applies
		// to "/sys".
		if u.Target == "/proc" || u.Target == "/sys" {
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
			// For sysfs we do something similar to procfs
			logrus.Debugf("Processing sysfs unmount: %v", u)
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

// Method handles umount syscall requests on sysbox-fs managed base mounts.
func (u *umountSyscallInfo) processUmount(
	mip *mountInfoParser) (*sysResponse, error) {

	// Create instructions payload.
	payload := u.createUmountPayload(mip)

	// Create nsenter-event envelope.
	nss := u.tracer.sms.nss
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
	mip *mountInfoParser) *[]*domain.UmountSyscallPayload {

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
			Target: info.MountPoint,
			Flags:  u.Flags,
		}
		payload = append(payload, newelem)
	}

	if mip.IsSysboxfsBaseMount(u.Target) {
		payload = append(payload, u.UmountSyscallPayload)
	}

	return &payload
}

func (u *umountSyscallInfo) String() string {
	return fmt.Sprintf("target = %s, flags = %#x", u.Target, u.Flags)
}
