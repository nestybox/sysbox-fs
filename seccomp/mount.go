package seccomp

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// MountSyscall information structure.
type mountSyscallInfo struct {
	syscallCtx                  // syscall generic info
	*domain.MountSyscallPayload // mount-syscall specific details
}

// Mount syscall processing wrapper instruction.
func (m *mountSyscallInfo) process() (*sysResponse, error) {

	mh := m.tracer.mountHelper

	// Handle requests that create a new mountpoint for filesystems managed by sysbox-fs
	if mh.isNewMount(m.Flags) {
		switch m.FsType {
		case "proc":
			logrus.Debugf("Processing new procfs mount: %v", m)
			return m.processProcMount()
		case "sysfs":
			logrus.Debugf("Processing new sysfs mount: %v", m)
			return m.processSysMount()
		case "nfs":
			logrus.Debugf("Processing new nfs mount: %v", m)
			return m.processNfsMount()
		}
	}

	// Mount moves are handled by the kernel
	if mh.isMove(m.Flags) {
		return m.tracer.createContinueResponse(m.reqId), nil
	}

	// Handle remount requests on filesystems managed by sysbox-fs
	if mh.isRemount(m.Flags) {

		mi, err := NewMountInfo(mh, m.cntr, m.pid)
		if err != nil {
			return nil, err
		}

		if mi.IsSysboxfsBaseMount(m.Target) || mi.IsSysboxfsSubmount(m.Target) {
			return m.processRemount(mi)
		}

		// No action by sysbox-fs
		return m.tracer.createContinueResponse(m.reqId), nil
	}

	// Handle bind-mount requests on filesystems managed by sysbox-fs.
	if mh.isBind(m.Flags) {

		mi, err := NewMountInfo(mh, m.cntr, m.pid)
		if err != nil {
			return nil, err
		}

		// Ignore binds-to-self requests on sysbox-fs managed submounts (these are already
		// bind-mounts, so we want to avoid the redundant bind mount for cosmetic purposes).
		if m.Source == m.Target && mi.IsSysboxfsSubmount(m.Target) {
			logrus.Debugf("Ignoring bind-to-self request of sysbox-fs managed submount at %s", m.Target)
			return m.tracer.createSuccessResponse(m.reqId), nil
		}

		// Ignore /dev/null bind mounts on sysbox-fs managed submounts which are already
		// bind-mounted to /dev/null (i.e., masked)
		if m.Source == "/dev/null" && mi.IsSysboxfsMaskedSubmount(m.Target) {
			logrus.Debugf("Ignoring /dev/null bind request over sysbox-fs masked submount at %s", m.Target)
			return m.tracer.createSuccessResponse(m.reqId), nil
		}

		// Process bind-mounts whose source is a sysbox-fs base mount (as we want the
		// submounts to also be bind-mounted at the target).
		if m.Source != m.Target && mi.IsSysboxfsBaseMount(m.Source) {
			return m.processBindMount(mi)
		}

		// No action by sysbox-fs
		return m.tracer.createContinueResponse(m.reqId), nil
	}

	// Hanlde propagation type changes on filesystems managed by sysbox-fs (no action required; let
	// the kernel handle mount propagation changes).
	if mh.hasPropagationFlag(m.Flags) {
		return m.tracer.createContinueResponse(m.reqId), nil
	}

	// No action by sysbox-fs otherwise
	return m.tracer.createContinueResponse(m.reqId), nil
}

// Method handles procfs mount syscall requests. As part of this function, we
// also create submounts under procfs (to expose, hide, or emulate resources).
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
		&domain.AllNSs,
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

// Method handles sysfs mount syscall requests. As part of this function, we
// also create submounts under sysfs (to expose, hide, or emulate resources).
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
		&domain.AllNSs,
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

// Method handles "nfs" mount syscall requests. Sysbox-fs does not manage nfs mounts
// per-se, but only "proxies" the nfs mount syscall. It does this in order to enable nfs
// to be mounted from within a (non init) user-ns.
func (m *mountSyscallInfo) processNfsMount() (*sysResponse, error) {

	// Create instruction's payload.
	payload := m.createNfsMountPayload()
	if payload == nil {
		return nil, fmt.Errorf("Could not construct nfsMount payload")
	}

	// Create nsenter-event envelope
	nss := m.tracer.sms.nss
	event := nss.NewEvent(
		m.syscallCtx.pid,
		&domain.AllNSsButUser,
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

// Build instructions payload required for remount operations.
func (m *mountSyscallInfo) createNfsMountPayload() *[]*domain.MountSyscallPayload {

	var payload []*domain.MountSyscallPayload

	// Payload instruction for re-mount request.
	payload = append(payload, m.MountSyscallPayload)

	return &payload
}

func (m *mountSyscallInfo) processRemount(mi *mountInfo) (*sysResponse, error) {

	// Create instruction's payload.
	payload := m.createRemountPayload(mi)
	if payload == nil {
		return nil, fmt.Errorf("Could not construct ReMount payload")
	}

	// Create nsenter-event envelope.
	nss := m.tracer.sms.nss
	event := nss.NewEvent(
		m.syscallCtx.pid,
		&domain.AllNSsButUser,
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

// Build instructions payload required for remount operations.
func (m *mountSyscallInfo) createRemountPayload(mi *mountInfo) *[]*domain.MountSyscallPayload {
	var payload []*domain.MountSyscallPayload

	mh := m.tracer.mountHelper

	// A procfs mount inside a sys container is a combination of a base proc mount plus
	// sysbox-fs submounts. If the remount is done on the base mount, its effect is also
	// applied to the submounts. If the remount is on a submount, its effect is limited to
	// that submount.

	submounts := []string{}

	if mi.IsSysboxfsBaseMount(m.Target) {
		submounts = mi.GetSysboxfsSubMounts(m.Target)
	} else {
		submounts = append(submounts, m.Target)
	}

	for _, subm := range submounts {
		submInfo := mi.GetInfo(subm)

		perMountFlags := mh.stringToFlags(submInfo.Opts)
		perFsFlags := mh.stringToFlags(submInfo.VfsOpts)
		submFlags := perMountFlags | perFsFlags

		// Pass the remount flags to the submounts
		submFlags |= unix.MS_REMOUNT

		if m.Flags&unix.MS_BIND == unix.MS_BIND {
			submFlags |= unix.MS_BIND
		}

		// We only propagate changes to the MS_RDONLY flag to the submounts. In the
		// future we could propagate other flags too.
		//
		// For MS_RDONLY:
		//
		// When set, we apply the read-only flag on all submounts.
		// When cleared, we apply the read-write flag on all submounts which are not
		// mounted as read-only in the container's /proc

		if m.Flags&unix.MS_RDONLY == unix.MS_RDONLY {
			submFlags |= unix.MS_RDONLY
		} else {
			if !mi.IsSysboxfsRoSubmount(subm) {
				submFlags = submFlags &^ unix.MS_RDONLY
			}
		}

		// Leave the filesystem options (aka data) unchanged; note that since mountinfo
		// provides them mixed with flags, we must filter the options out.
		submOpts := mh.filterFsFlags(submInfo.VfsOpts)

		newelem := &domain.MountSyscallPayload{
			Source: "",
			Target: subm,
			FsType: "",
			Flags:  submFlags,
			Data:   submOpts,
		}
		payload = append(payload, newelem)
	}

	if mi.IsSysboxfsBaseMount(m.Target) {
		payload = append(payload, m.MountSyscallPayload)
	}

	return &payload
}

// Method handles bind-mount requests whose source is a mountpoint managed by sysbox-fs.
func (m *mountSyscallInfo) processBindMount(mi *mountInfo) (*sysResponse, error) {

	// Create instruction's payload.
	payload := m.createBindMountPayload(mi)
	if payload == nil {
		return nil, fmt.Errorf("Could not construct ReMount payload")
	}

	// Create nsenter-event envelope.
	nss := m.tracer.sms.nss
	event := nss.NewEvent(
		m.syscallCtx.pid,
		&domain.AllNSs,
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

// Build instructions payload required for bind-mount operations.
func (m *mountSyscallInfo) createBindMountPayload(mi *mountInfo) *[]*domain.MountSyscallPayload {
	var payload []*domain.MountSyscallPayload

	// A procfs mount inside a sys container is a combination of a base proc mount plus
	// sysbox-fs submounts. If the bind-mount is done on the base mount, its effect is also
	// applied to the submounts.

	payload = append(payload, m.MountSyscallPayload)

	// If the bind-mount is recursive, then the kernel will do the remounting of the
	// submounts. No need for us to do anything.
	if m.Flags&unix.MS_REC == unix.MS_REC {
		return &payload
	}

	// If the bind-mount is not recursive, then we do the bind-mount of the sysbox-fs
	// managed submounts explicitly.
	submounts := mi.GetSysboxfsSubMounts(m.Source)

	for _, subm := range submounts {
		relTarget := strings.TrimPrefix(subm, m.Source)
		subTarget := filepath.Join(m.Target, relTarget)

		newelem := &domain.MountSyscallPayload{
			Source: subm,
			Target: subTarget,
			FsType: "",
			Flags:  m.Flags,
			Data:   "",
		}
		payload = append(payload, newelem)
	}

	return &payload
}

func (m *mountSyscallInfo) String() string {
	return fmt.Sprintf("source: %s, target = %s, fstype = %s, flags = %#x, data = %s",
		m.Source, m.Target, m.FsType, m.Flags, m.Data)
}
