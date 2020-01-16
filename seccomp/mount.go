package seccomp

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/nestybox/sysbox-fs/domain"
	libcontainer "github.com/nestybox/sysbox-runc/libcontainer/mount"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// MountSyscall information structure.
type mountSyscallInfo struct {
	syscallCtx                  // syscall generic info
	*domain.MountSyscallPayload // mount-syscall specific details
}

//
func (m *mountSyscallInfo) action() syscallResponse {

	logrus.Errorf("Position 1")

	//
	if (m.FsType == "proc" || m.FsType == "sysfs") &&
		m.Flags&^sysboxProcSkipMountFlags == m.Flags {
		return SYSCALL_PROCESS
	}

	logrus.Errorf("Position 2")

	// Address bind-mount requests.
	if m.Flags&unix.MS_BIND == unix.MS_BIND {

		logrus.Errorf("Position 3")

		if m.isSysboxfsMount(m.Target) {

			// If not a remount operation.
			if m.Flags&unix.MS_REMOUNT != unix.MS_REMOUNT {

				logrus.Errorf("Position 4")

				// If target is a sysbox-fs mountpoint, then just fake it.
				//if m.Source == m.Target || m.Source == "/dev/null" {
				logrus.Errorf("Position 5")
				return SYSCALL_SUCCESS
				logrus.Errorf("Position 6")

			} else {
				logrus.Errorf("Position 7")
				return SYSCALL_PROCESS
			}
		}
	}

	logrus.Errorf("Position 9")
	return SYSCALL_CONTINUE
}

// MountSyscall processing wrapper instruction.
func (m *mountSyscallInfo) process() (*sysResponse, error) {

	switch m.Source {

	case "proc":
		return m.processProcMount()

	case "sysfs":
		return m.processSysMount()

	default:
		return m.processReMount()
	}

	return nil, fmt.Errorf("Unsupported mount syscall request")
}

// Method handles "/proc" mount syscall requests. As part of this function, we
// also bind-mount all the sysbox-fs' emulated resources into the mount target
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
			responseMsg.Payload.(error).(syscall.Errno))

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
	procBindMounts := m.tracer.mountInfo.procMounts
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
		logrus.Errorf("payload 1: %v", newelem)
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
		logrus.Errorf("payload 2: %v", newelem)
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
		logrus.Errorf("payload 3: %v", newelem)
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
				Flags:  unix.MS_RDONLY | unix.MS_BIND | unix.MS_REMOUNT | unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC,
				Data:   "",
			}
			payload = append(payload, newelem)
			logrus.Errorf("payload ro: %v", newelem)
		}
	}

	return &payload
}

// Method handles "/sys" mount syscall requests. As part of this function, we
// also bind-mount all the sysbox-fs' emulated resources into the mount target
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
			responseMsg.Payload.(error).(syscall.Errno))

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
	sysBindMounts := m.tracer.mountInfo.sysMounts
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

	// Note 1)
	//
	// 1) If "/sys" is to be mounted as read-only, we want this requirement to
	// extend to all of its inner bind-mounts.
	if m.Flags&unix.MS_RDONLY == unix.MS_RDONLY {

		for _, v := range sysBindMounts {
			relPath := strings.TrimPrefix(v, "/sys")

			newelem := &domain.MountSyscallPayload{
				Source: "",
				Target: filepath.Join(m.Target, relPath),
				FsType: "",
				Flags:  unix.MS_RDONLY | unix.MS_BIND | unix.MS_REMOUNT | unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC,
				Data:   "",
			}
			payload = append(payload, newelem)
		}
	}

	return &payload
}

// Method handles remount syscall requests within procfs and sysfs node hierarchy.
func (m *mountSyscallInfo) processReMount() (*sysResponse, error) {

	// Obtain the existing flags of the mount target on which we are trying
	// to operate. The goal here is to avoid pushing flags that don't fully
	// match the ones kernel is aware of for this resource.
	//
	// TODO: Optimize -- technically, there's no need to parse /proc/pid/mountinfo
	// again.
	curFlags, err := m.getMountFlags(m.Target)
	if err != nil {
		return nil, err
	}

	// Adjust mount-flags to incorporate (or eliminate) 'read-only' flag based on
	// the mount requirements, as well as the existing kernel flags for
	if m.Flags&unix.MS_RDONLY == unix.MS_RDONLY {
		m.Flags = curFlags | unix.MS_RDONLY | unix.MS_BIND | unix.MS_REMOUNT
	} else {
		m.Flags = (curFlags &^ unix.MS_RDONLY) | unix.MS_BIND | unix.MS_REMOUNT
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
	err = nss.SendRequestEvent(event)
	if err != nil {
		return nil, err
	}

	// Obtain nsenter-event response.
	responseMsg := nss.ReceiveResponseEvent(event)
	if responseMsg.Type == domain.ErrorResponse {
		resp := m.tracer.createErrorResponse(
			m.reqId,
			responseMsg.Payload.(error).(syscall.Errno))

		return resp, nil
	}

	return m.tracer.createSuccessResponse(m.reqId), nil
}

//
func (m *mountSyscallInfo) getMountFlags(target string) (uint64, error) {

	info, err := libcontainer.GetMountAtForPid(m.pid, target)
	if err != nil {
		return 0, err
	}

	return m.tracer.mountInfo.stringToFlags(info.Opts), nil
}

//
func (m *mountSyscallInfo) isSysboxfsMount(target string) bool {

	nodeType := m.sysboxfsMountType(m.pid, target)

	switch nodeType {
	case bindMount:
		return true
	case specMount:
		return true
	case procfsMount:
		return true
	case sysfsMount:
		return true
	}

	return false
}

//
func (m *mountSyscallInfo) sysboxfsMountType(pid uint32, target string) sysboxMountType {

	//
	if m.syscallCtx.cntr.IsSpecPath(target) {
		return specMount
	}

	//
	if m.tracer.mountInfo.isBindMount(target) {
		return bindMount
	}

	return getMountInfoType(m.pid, target)
}

func (m *mountSyscallInfo) string() string {

	result := "source: " + m.Source + " target: " + m.Target +
		" fstype: " + m.FsType + " flags: " +
		strconv.FormatUint(m.Flags, 10) + " data: " + m.Data

	return result
}
