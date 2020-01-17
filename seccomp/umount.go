package seccomp

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/sirupsen/logrus"
)

type umountSyscallInfo struct {
	syscallCtx                   // syscall generic info
	*domain.UmountSyscallPayload // unmount-syscall specific details
}

func (u *umountSyscallInfo) action() syscallResponse {

	logrus.Errorf("Umount Position 1")

	// Obtain the fstype associated to this mount target as per sysbox-fs
	// mount-type classification.
	u.SysFsType = uint8(u.sysboxfsUmountType(u.pid, u.Target))

	switch sysboxMountType(u.SysFsType) {

	case procfsMount:
		logrus.Errorf("Umount Position 2")
		return SYSCALL_PROCESS

	case sysfsMount:
		logrus.Errorf("Umount Position 3")
		return SYSCALL_PROCESS

	case bindMount:
		logrus.Errorf("Umount Position 4")
		return SYSCALL_SUCCESS

	case specMount:
		logrus.Errorf("Umount Position 5")
		return SYSCALL_SUCCESS
	}

	logrus.Errorf("Umount Position 6")
	return SYSCALL_CONTINUE
}

// MountSyscall processing wrapper instruction.
func (u *umountSyscallInfo) process() (*sysResponse, error) {

	switch sysboxMountType(u.SysFsType) {

	case procfsMount:
		return u.processProcUmount()

	case sysfsMount:
		return u.processSysUmount()
	}

	return nil, fmt.Errorf("Unsupported umount syscall request")
}

// Method handles "/proc" mount syscall requests. As part of this function, we
// also bind-mount all the sysbox-fs' emulated resources into the mount target
// requested by the user. Our goal here is to extend sysbox-fs' virtualization
// capabilities to L2 app containers and/or L1 chroot'ed environments.
func (u *umountSyscallInfo) processProcUmount() (*sysResponse, error) {

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
			responseMsg.Payload.(error).(syscall.Errno))

		return resp, nil
	}

	return u.tracer.createSuccessResponse(u.reqId), nil
}

// Build instructions payload required to unmount "/proc" subtree.
func (u *umountSyscallInfo) createProcPayload() *[]*domain.UmountSyscallPayload {

	var payload []*domain.UmountSyscallPayload

	// Sysbox-fs "/proc" bind-mounts.
	procBindMounts := u.tracer.mountInfo.procMounts
	for _, v := range procBindMounts {
		relPath := strings.TrimPrefix(v, "/proc")

		newelem := &domain.UmountSyscallPayload{
			Target: filepath.Join(u.Target, relPath),
			Flags:  0,
		}
		payload = append(payload, newelem)
		logrus.Errorf("umount payload 1: %v", newelem)
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
		logrus.Errorf("umount payload 2: %v", newelem)
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
		logrus.Errorf("umount payload 3: %v", newelem)
	}

	// Payload instruction for original "/proc" umount request.
	payload = append(payload, u.UmountSyscallPayload)

	return &payload
}

// Method handles "/sys" mount syscall requests. As part of this function, we
// also bind-mount all the sysbox-fs' emulated resources into the mount target
// requested by the user.
func (u *umountSyscallInfo) processSysUmount() (*sysResponse, error) {

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
			responseMsg.Payload.(error).(syscall.Errno))

		return resp, nil
	}

	return u.tracer.createSuccessResponse(u.reqId), nil
}

// Build instructions payload required to unmount "/sys" subtree.
func (u *umountSyscallInfo) createSysPayload() *[]*domain.UmountSyscallPayload {

	var payload []*domain.UmountSyscallPayload

	// Sysbox-fs "/sys" bind-mounts.
	sysBindMounts := u.tracer.mountInfo.sysMounts
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

func (u *umountSyscallInfo) sysboxfsUmountType(pid uint32, target string) sysboxMountType {

	//
	if u.syscallCtx.cntr.IsSpecPath(target) {
		return specMount
	}

	//
	if u.tracer.mountInfo.isBindMount(target) {
		return bindMount
	}

	return getMountInfoType(u.pid, target)
}

func (u *umountSyscallInfo) string() string {

	result := "target: " + u.Target + " flags: " + strconv.FormatUint(u.Flags, 10)

	return result
}
