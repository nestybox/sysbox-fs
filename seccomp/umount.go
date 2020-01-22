package seccomp

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
)

type umountSyscallInfo struct {
	syscallCtx                   // syscall generic info
	*domain.UmountSyscallPayload // unmount-syscall specific details
}

// MountSyscall processing wrapper instruction.
func (u *umountSyscallInfo) process() (*sysResponse, error) {

	// Obtain the fstype associated to this mount target as per sysbox-fs
	// mount-type classification.
	fsType, err :=
		u.tracer.mountHelper.sysboxfsMountType(u.pid, u.cntr, u.Target, nil)
	if err != nil {
		return u.tracer.createContinueResponse(u.reqId), nil
	}

	u.FsType = uint8(fsType)

	switch fsType {

	case PROCFS_MOUNT:
		return u.processProcUmount()

	case SYSFS_MOUNT:
		return u.processSysUmount()

	case REAL_PROCFS_MOUNT:
		return u.tracer.createErrorResponse(u.reqId, syscall.EINVAL), nil

	case BIND_MOUNT:
		return u.tracer.createSuccessResponse(u.reqId), nil

	case SPEC_MOUNT:
		return u.tracer.createSuccessResponse(u.reqId), nil

	case INVALID_MOUNT:
		return u.tracer.createErrorResponse(u.reqId, syscall.EINVAL), nil
	}

	return u.tracer.createContinueResponse(u.reqId), nil
}

// Method handles "/proc" umount syscall requests. As part of this function, we
// also unmount all the procfs emulated resources.
func (u *umountSyscallInfo) processProcUmount() (*sysResponse, error) {

	// Create instructions payload.
	payload := u.createProcPayload()
	if payload == nil {
		return nil, fmt.Errorf("Could not construct procUmount payload")
	}

	// Create nsenter-event envelope.
	nss := u.tracer.sms.nss
	event := nss.NewEvent(
		u.syscallCtx.pid,
		[]domain.NStype{
			string(domain.NStypeUser),
			string(domain.NStypePid),
			string(domain.NStypeNet),
			string(domain.NStypeMount),
			string(domain.NStypeIpc),
			string(domain.NStypeCgroup),
			string(domain.NStypeUts),
		},
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

// Build instructions payload required to unmount "/proc" subtree.
func (u *umountSyscallInfo) createProcPayload() *[]*domain.UmountSyscallPayload {

	var payload []*domain.UmountSyscallPayload

	// Sysbox-fs "/proc" bind-mounts.
	procBindMounts := u.tracer.mountHelper.procMounts
	for _, v := range procBindMounts {
		relPath := strings.TrimPrefix(v, "/proc")

		newelem := &domain.UmountSyscallPayload{
			Target: filepath.Join(u.Target, relPath),
			Flags:  0,
		}
		payload = append(payload, newelem)
	}

	// Container-specific read-only paths.
	procRoPaths := u.cntr.ProcRoPaths()
	for _, v := range procRoPaths {
		if !fileExists(v) {
			continue
		}
		relPath := strings.TrimPrefix(v, "/proc")

		newelem := &domain.UmountSyscallPayload{
			Target: filepath.Join(u.Target, relPath),
			Flags:  0,
		}
		payload = append(payload, newelem)
	}

	// Container-specific masked paths.
	procMaskPaths := u.cntr.ProcMaskPaths()
	for _, v := range procMaskPaths {
		if !fileExists(v) {
			continue
		}
		relPath := strings.TrimPrefix(v, "/proc")

		newelem := &domain.UmountSyscallPayload{
			Target: filepath.Join(u.Target, relPath),
			Flags:  0,
		}
		payload = append(payload, newelem)
	}

	// Payload instruction for original "/proc" umount request.
	payload = append(payload, u.UmountSyscallPayload)

	return &payload
}

// Method handles "/sys" unmount syscall requests. As part of this function, we
// also unmount all the sysfs emulated resources.
func (u *umountSyscallInfo) processSysUmount() (*sysResponse, error) {

	// Create instructions payload.
	payload := u.createSysPayload()
	if payload == nil {
		return nil, fmt.Errorf("Could not construct sysUmount payload")
	}

	// Create nsenter-event envelope.
	nss := u.tracer.sms.nss
	event := nss.NewEvent(
		u.syscallCtx.pid,
		[]domain.NStype{
			string(domain.NStypeUser),
			string(domain.NStypePid),
			string(domain.NStypeNet),
			string(domain.NStypeMount),
			string(domain.NStypeIpc),
			string(domain.NStypeCgroup),
			string(domain.NStypeUts),
		},
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

// Build instructions payload required to unmount "/sys" subtree.
func (u *umountSyscallInfo) createSysPayload() *[]*domain.UmountSyscallPayload {

	var payload []*domain.UmountSyscallPayload

	// Sysbox-fs "/sys" bind-mounts.
	sysBindMounts := u.tracer.mountHelper.sysMounts
	for _, v := range sysBindMounts {
		relPath := strings.TrimPrefix(v, "/sys")

		newelem := &domain.UmountSyscallPayload{
			Target: filepath.Join(u.Target, relPath),
			Flags:  0,
		}
		payload = append(payload, newelem)
	}

	// Payload instruction for original "/proc" umount request.
	payload = append(payload, u.UmountSyscallPayload)

	return &payload
}

func (u *umountSyscallInfo) string() string {

	result := "target: " + u.Target + " flags: " + strconv.FormatUint(u.Flags, 10)

	return result
}
