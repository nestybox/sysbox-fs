package seccomp

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
	"golang.org/x/sys/unix"
)

// MountSyscall information structure.
type mountSyscallInfo struct {
	syscallCtx                  // syscall generic info
	*domain.MountSyscallPayload // mount-syscall specific details
}

// MountSyscall processing wrapper instruction.
func (m *mountSyscallInfo) process() (*sysResponse, error) {

	if m.Flags&^sysboxProcSkipMountFlags == m.Flags {
		if m.FsType == "proc" {
			return m.processProcMount()
		} else if m.FsType == "sysfs" {
			return m.processSysMount()
		}
		return m.tracer.createContinueResponse(m.reqId), nil
	}

	// Handle bind-mount requests.
	if m.Flags&unix.MS_BIND == unix.MS_BIND {

		// If dealing with a 'pure' bind-mount request (no 'remount' flag),
		// determine if the operation needs to be disregarded to avoid duplicated
		// mount entries. This would happen for all the elements that are implicitly
		// mounted as part of procMount() and sysMount() execution. Notice that to
		// narrow down the number of skip instructions, we make use of the
		// "source==target" and "source==/dev/null" filters as these ones match the
		// signature of the resources sysbox-fs emulates.
		if m.Flags&unix.MS_REMOUNT != unix.MS_REMOUNT {
			if (m.Source == m.Target || m.Source == "/dev/null") &&
				m.tracer.mountHelper.isSysboxfsMount(m.pid, m.cntr, m.Target, &m.CurFlags) {
				return m.tracer.createSuccessResponse(m.reqId), nil
			}
		} else {
			if m.tracer.mountHelper.isSysboxfsMount(m.pid, m.cntr, m.Target, &m.CurFlags) {
				return m.processReMount()
			}
		}
	}

	return m.tracer.createContinueResponse(m.reqId), nil
}

// Method handles "/proc" mount syscall requests. As part of this function, we
// also bind-mount all the procfs emulated resources into the mount target
// requested by the user. Our goal here is to extend sysbox-fs' virtualization
// capabilities to L2 app containers and/or L1 chroot'ed environments.
func (m *mountSyscallInfo) processProcMount() (*sysResponse, error) {

	// Create instructions payload.
	payload := m.createProcPayload()
	if payload == nil {
		return nil, fmt.Errorf("Could not construct procMount payload")
	}

	// Create nsenter-event envelope.
	nss := m.tracer.sms.nss
	event := nss.NewEvent(
		m.syscallCtx.pid,
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
			Type:    domain.MountSyscallRequest,
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
		resp := m.tracer.createErrorResponse(
			m.reqId,
			responseMsg.Payload.(fuse.IOerror).Code)

		return resp, nil
	}

	return m.tracer.createSuccessResponse(m.reqId), nil
}

// Build instructions payload required to mount "/proc" subtree.
func (m *mountSyscallInfo) createProcPayload() *[]*domain.MountSyscallPayload {

	var payload []*domain.MountSyscallPayload

	// Payload instruction for original "/proc" mount request.
	payload = append(payload, m.MountSyscallPayload)

	// Sysbox-fs "/proc" bind-mounts.
	procBindMounts := m.tracer.mountHelper.procMounts
	for _, v := range procBindMounts {
		relPath := strings.TrimPrefix(v, "/proc")

		newelem := &domain.MountSyscallPayload{
			Source: v,
			Target: filepath.Join(m.Target, relPath),
			FsType: "",
			Flags:  unix.MS_BIND,
			Data:   "",
		}
		payload = append(payload, newelem)
	}

	// Container-specific read-only paths.
	procRoPaths := m.cntr.ProcRoPaths()
	for _, v := range procRoPaths {
		if !fileExists(v) {
			continue
		}
		relPath := strings.TrimPrefix(v, "/proc")

		newelem := &domain.MountSyscallPayload{
			Source: v,
			Target: filepath.Join(m.Target, relPath),
			FsType: "",
			Flags:  unix.MS_BIND,
			Data:   "",
		}
		payload = append(payload, newelem)
	}

	// Container-specific masked paths.
	procMaskPaths := m.cntr.ProcMaskPaths()
	for _, v := range procMaskPaths {
		if !fileExists(v) {
			continue
		}
		relPath := strings.TrimPrefix(v, "/proc")

		newelem := &domain.MountSyscallPayload{
			Source: v,
			Target: filepath.Join(m.Target, relPath),
			FsType: "",
			Flags:  unix.MS_BIND,
			Data:   "",
		}
		payload = append(payload, newelem)
	}

	// If "/proc" is to be mounted as read-only, we want this requirement to
	// extend to all of its inner bind-mounts.
	if m.Flags&unix.MS_RDONLY == unix.MS_RDONLY {

		for _, v := range procBindMounts {
			relPath := strings.TrimPrefix(v, "/proc")

			newelem := &domain.MountSyscallPayload{
				Source: "",
				Target: filepath.Join(m.Target, relPath),
				FsType: "",
				// TODO: Avoid hard-coding these flags.
				Flags: unix.MS_RDONLY | unix.MS_BIND | unix.MS_REMOUNT | unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC,
				Data:  "",
			}
			payload = append(payload, newelem)
		}
	}

	return &payload
}

// Method handles "/sys" mount syscall requests. As part of this function, we
// also bind-mount all the sysfs emulated resources into the mount target
// requested by the user.
func (m *mountSyscallInfo) processSysMount() (*sysResponse, error) {

	// Create instruction's payload.
	payload := m.createSysPayload()
	if payload == nil {
		return nil, fmt.Errorf("Could not construct sysfsMount payload")
	}

	// Create nsenter-event envelope.
	nss := m.tracer.sms.nss
	event := nss.NewEvent(
		m.syscallCtx.pid,
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
			Type:    domain.MountSyscallRequest,
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
		resp := m.tracer.createErrorResponse(
			m.reqId,
			responseMsg.Payload.(fuse.IOerror).Code)

		return resp, nil
	}

	return m.tracer.createSuccessResponse(m.reqId), nil
}

// Build instructions payload required to mount "/sys" subtree.
func (m *mountSyscallInfo) createSysPayload() *[]*domain.MountSyscallPayload {

	var payload []*domain.MountSyscallPayload

	// Payload instruction for original "/sys" mount request.
	payload = append(payload, m.MountSyscallPayload)

	// Sysbox-fs "/sys" bind-mounts.
	sysBindMounts := m.tracer.mountHelper.sysMounts
	for _, v := range sysBindMounts {
		relPath := strings.TrimPrefix(v, "/sys")

		newelem := &domain.MountSyscallPayload{
			Source: v,
			Target: filepath.Join(m.Target, relPath),
			FsType: "",
			Flags:  unix.MS_BIND,
			Data:   "",
		}
		payload = append(payload, newelem)
	}

	// If "/sys" is to be mounted as read-only, we want this requirement to
	// extend to all of its inner bind-mounts.
	if m.Flags&unix.MS_RDONLY == unix.MS_RDONLY {

		for _, v := range sysBindMounts {
			relPath := strings.TrimPrefix(v, "/sys")

			newelem := &domain.MountSyscallPayload{
				Source: "",
				Target: filepath.Join(m.Target, relPath),
				FsType: "",
				// TODO: Avoid hard-coding these flags.
				Flags: unix.MS_RDONLY | unix.MS_BIND | unix.MS_REMOUNT | unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC,
				Data:  "",
			}
			payload = append(payload, newelem)
		}
	}

	return &payload
}

// Method handles remount syscall requests within procfs and sysfs node hierarchy.
func (m *mountSyscallInfo) processReMount() (*sysResponse, error) {

	// Adjust mount-flags to incorporate (or eliminate) 'read-only' flag based on
	// the mount requirements, as well as the existing kernel flags.
	if m.Flags&unix.MS_RDONLY == unix.MS_RDONLY {
		m.Flags = m.CurFlags | unix.MS_RDONLY | unix.MS_BIND | unix.MS_REMOUNT
	} else {
		m.Flags = (m.CurFlags &^ unix.MS_RDONLY) | unix.MS_BIND | unix.MS_REMOUNT
	}

	// Create nsenter-event envelope.
	nss := m.tracer.sms.nss
	event := nss.NewEvent(
		m.syscallCtx.pid,
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
			Type:    domain.MountSyscallRequest,
			Payload: []*domain.MountSyscallPayload{m.MountSyscallPayload},
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
		resp := m.tracer.createErrorResponse(
			m.reqId,
			responseMsg.Payload.(fuse.IOerror).Code)

		return resp, nil
	}

	return m.tracer.createSuccessResponse(m.reqId), nil
}

func (m *mountSyscallInfo) string() string {

	result := "source: " + m.Source + " target: " + m.Target +
		" fstype: " + m.FsType + " flags: " +
		strconv.FormatUint(m.Flags, 10) + " data: " + m.Data

	return result
}
