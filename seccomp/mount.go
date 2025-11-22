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
	"golang.org/x/sys/unix"
)

// MountSyscall information structure.
type mountSyscallInfo struct {
	syscallCtx                  // syscall generic info
	*domain.MountSyscallPayload // mount-syscall specific details
}

// Mount syscall processing wrapper instruction.
func (m *mountSyscallInfo) process() (*sysResponse, error) {

	mts := m.tracer.service.mts
	if mts == nil {
		return nil, fmt.Errorf("unexpected mount-service handler")
	}
	mh := mts.MountHelper()
	if mh == nil {
		return nil, fmt.Errorf("unexpected mount-service-helper handler")
	}

	// Adjust mount attributes attending to the process' root path.
	m.targetAdjust()

	// Ensure that the mountInfoDB corresponding to the sys-container hosting
	// this process has been already built. This info is necessary to be able
	// to discern between 'initial' and 'regular' mounts, which is required
	// for the proper operation of the mount-hardening feature.
	if !m.cntr.IsMountInfoInitialized() {
		if err := m.cntr.InitializeMountInfo(); err != nil {
			return nil, err
		}
	}

	// Handle requests that create a new mountpoint for filesystems managed by
	// sysbox-fs.
	if mh.IsNewMount(m.Flags) {

		mip, err := mts.NewMountInfoParser(m.cntr, m.processInfo, true, true, false)
		if err != nil {
			return nil, err
		}

		switch m.FsType {
		case "proc":
			return m.processProcMount(mip)
		case "sysfs":
			return m.processSysMount(mip)
		case "overlay":
			return m.processOverlayMount(mip)
		case "nfs":
			return m.processNfsMount(mip)
		}
	}

	// Mount moves are handled by the kernel
	if mh.IsMove(m.Flags) {
		return m.tracer.createContinueResponse(m.reqId), nil
	}

	// Handle propagation type changes on filesystems managed by sysbox-fs (no
	// action required; let the kernel handle mount propagation changes).
	if mh.HasPropagationFlag(m.Flags) {
		return m.tracer.createContinueResponse(m.reqId), nil
	}

	// Handle remount requests on filesystems managed by sysbox-fs
	if mh.IsRemount(m.Flags) {

		mip, err := mts.NewMountInfoParser(m.cntr, m.processInfo, true, true, false)
		if err != nil {
			return nil, err
		}

		if ok, resp := m.remountAllowed(mip); !ok {
			return resp, nil
		}

		if mip.IsSysboxfsBaseMount(m.Target) ||
			mip.IsSysboxfsSubmount(m.Target) {
			return m.processRemount(mip)
		}

		// No action by sysbox-fs
		return m.tracer.createContinueResponse(m.reqId), nil
	}

	// Handle bind-mount requests on filesystems managed by sysbox-fs.
	if mh.IsBind(m.Flags) {

		mip, err := mts.NewMountInfoParser(m.cntr, m.processInfo, true, true, false)
		if err != nil {
			return nil, err
		}

		// Ignore binds-to-self requests on sysbox-fs managed submounts (these
		// are already bind-mounts, so we want to avoid the redundant bind mount
		// for cosmetic purposes).
		if m.Source == m.Target && mip.IsSysboxfsSubmount(m.Target) {
			logrus.Debugf("Ignoring bind-to-self request of sysbox-fs managed submount at %s",
				m.Target)
			return m.tracer.createSuccessResponse(m.reqId), nil
		}

		// Ignore /dev/null bind mounts on sysbox-fs managed submounts which are
		// already bind-mounted to /dev/null (i.e., masked).
		if m.Source == "/dev/null" && mip.IsSysboxfsMaskedSubmount(m.Target) {
			logrus.Debugf("Ignoring /dev/null bind request over sysbox-fs masked submount at %s",
				m.Target)
			return m.tracer.createSuccessResponse(m.reqId), nil
		}

		// Process bind-mounts whose source is a sysbox-fs base mount (as we
		// want the submounts to also be bind-mounted at the target).
		if m.Source != m.Target && mip.IsSysboxfsBaseMount(m.Source) {
			return m.processBindMount(mip)
		}

		// No action by sysbox-fs
		return m.tracer.createContinueResponse(m.reqId), nil
	}

	// No action by sysbox-fs otherwise
	return m.tracer.createContinueResponse(m.reqId), nil
}

// Method handles procfs mount syscall requests. As part of this function, we
// also create submounts under procfs (to expose, hide, or emulate resources).
func (m *mountSyscallInfo) processProcMount(
	mip domain.MountInfoParserIface) (*sysResponse, error) {

	logrus.Debugf("Processing new procfs mount: %v", m)

	// Create instructions payload.
	payload := m.createProcPayload(mip)
	if payload == nil {
		return nil, fmt.Errorf("Could not construct procMount payload")
	}

	// Create nsenter-event envelope.
	nss := m.tracer.service.nss
	event := nss.NewEvent(
		m.syscallCtx.pid,
		m.syscallCtx.uid,
		m.syscallCtx.gid,
		&domain.AllNSs,
		0,
		&domain.NSenterMessage{
			Type:    domain.MountSyscallRequest,
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
		resp := m.tracer.createErrorResponse(
			m.reqId,
			responseMsg.Payload.(fuse.IOerror).Code)
		return resp, nil
	}

	// Chown the proc mount to the requesting process' uid:gid (typically
	// root:root) as otherwise it will show up as "nobody:nogroup".
	//
	// NOTE: for now we skip the chown if the mount is read-only, as otherwise
	// the chown will fail. This means that read-only mounts of proc will still
	// show up as "nobody:nouser" inside the sys container (e.g., in inner
	// containers). Solving this would require that we first mount proc, then
	// chown, then remount read-only. This would in turn require 3 nsenter
	// events, because the namespaces that we must enter for each are not the
	// same (in particular for the chown to succeed, we must not enter the
	// user-ns of the container).

	if m.Flags&unix.MS_RDONLY == unix.MS_RDONLY {
		return m.tracer.createSuccessResponse(m.reqId), nil
	}

	ci := &chownSyscallInfo{
		path:     m.Target,
		ownerUid: int64(m.uid),
		ownerGid: int64(m.gid),
	}

	ci.syscallCtx.reqId = m.reqId
	ci.syscallCtx.pid = m.pid
	ci.syscallCtx.tracer = m.tracer

	return ci.processChownNSenter(domain.AllNSsButUser)
}

// Build instructions payload required to mount "/proc" subtree.
func (m *mountSyscallInfo) createProcPayload(
	mip domain.MountInfoParserIface) *[]*domain.MountSyscallPayload {

	var payload []*domain.MountSyscallPayload

	// Payload instruction for original "/proc" mount request.
	payload = append(payload, m.MountSyscallPayload)

	// If procfs has a read-only attribute at super-block level, we must also
	// apply this to the new mountpoint (otherwise we will get a permission
	// denied from the kernel when doing the mount).
	procInfo := mip.GetInfo("/proc")
	if procInfo != nil {
		if _, ok := procInfo.VfsOptions["ro"]; ok {
			payload[0].Flags |= unix.MS_RDONLY
		}
	}

	mh := m.tracer.service.mts.MountHelper()

	// Sysbox-fs "/proc" bind-mounts.
	procBindMounts := mh.ProcMounts()
	for _, v := range procBindMounts {
		relPath := strings.TrimPrefix(v, "/proc")

		newelem := &domain.MountSyscallPayload{
			domain.NSenterMsgHeader{},
			domain.Mount{
				Source: v,
				Target: filepath.Join(m.Target, relPath),
				FsType: "",
				Flags:  unix.MS_BIND,
				Data:   "",
			},
		}
		payload = append(payload, newelem)
	}

	// Container-specific read-only paths.
	procRoPaths := m.cntr.ProcRoPaths()
	for _, v := range procRoPaths {
		if !domain.FileExists(v) {
			continue
		}
		relPath := strings.TrimPrefix(v, "/proc")

		newelem := &domain.MountSyscallPayload{
			domain.NSenterMsgHeader{},
			domain.Mount{
				Source: v,
				Target: filepath.Join(m.Target, relPath),
				FsType: "",
				Flags:  unix.MS_BIND,
				Data:   "",
			},
		}
		payload = append(payload, newelem)
	}

	// Container-specific masked paths.
	procMaskPaths := m.cntr.ProcMaskPaths()
	for _, v := range procMaskPaths {
		if !domain.FileExists(v) {
			continue
		}
		relPath := strings.TrimPrefix(v, "/proc")

		newelem := &domain.MountSyscallPayload{
			domain.NSenterMsgHeader{},
			domain.Mount{
				Source: v,
				Target: filepath.Join(m.Target, relPath),
				FsType: "",
				Flags:  unix.MS_BIND,
				Data:   "",
			},
		}
		payload = append(payload, newelem)
	}

	// If "/proc" is to be mounted as read-only, we want this requirement to
	// extend to all of its inner bind-mounts.
	if m.Flags&unix.MS_RDONLY == unix.MS_RDONLY {

		for _, v := range procBindMounts {
			relPath := strings.TrimPrefix(v, "/proc")

			newelem := &domain.MountSyscallPayload{
				domain.NSenterMsgHeader{},
				domain.Mount{
					Source: "",
					Target: filepath.Join(m.Target, relPath),
					FsType: "",
					// TODO: Avoid hard-coding these flags.
					Flags: unix.MS_RDONLY | unix.MS_BIND | unix.MS_REMOUNT | unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC,
					Data:  "",
				},
			}
			payload = append(payload, newelem)
		}
	}

	return &payload
}

// Method handles sysfs mount syscall requests. As part of this function, we
// also create submounts under sysfs (to expose, hide, or emulate resources).
func (m *mountSyscallInfo) processSysMount(
	mip domain.MountInfoParserIface) (*sysResponse, error) {

	logrus.Debugf("Processing new sysfs mount: %v", m)

	// Create instruction's payload.
	payload := m.createSysPayload(mip)
	if payload == nil {
		return nil, fmt.Errorf("Could not construct sysfsMount payload")
	}

	// Create nsenter-event envelope.
	nss := m.tracer.service.nss
	event := nss.NewEvent(
		m.syscallCtx.pid,
		m.syscallCtx.uid,
		m.syscallCtx.gid,
		&domain.AllNSs,
		0,
		&domain.NSenterMessage{
			Type:    domain.MountSyscallRequest,
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
		resp := m.tracer.createErrorResponse(
			m.reqId,
			responseMsg.Payload.(fuse.IOerror).Code)
		return resp, nil
	}

	return m.tracer.createSuccessResponse(m.reqId), nil
}

// Build instructions payload required to mount "/sys" subtree.
func (m *mountSyscallInfo) createSysPayload(
	mip domain.MountInfoParserIface) *[]*domain.MountSyscallPayload {

	var payload []*domain.MountSyscallPayload

	// Payload instruction for original "/sys" mount request.
	payload = append(payload, m.MountSyscallPayload)

	// If sysfs has a read-only attribute at super-block level, we must also
	// apply this to the new mountpoint (otherwise we will get a permission
	// denied from the kernel when doing the mount).
	sysInfo := mip.GetInfo("/sys")
	if sysInfo != nil {
		if _, ok := sysInfo.VfsOptions["ro"]; ok {
			payload[0].Flags |= unix.MS_RDONLY
		}
	}

	mh := m.tracer.service.mts.MountHelper()

	// Sysbox-fs "/sys" bind-mounts.
	sysBindMounts := mh.SysMounts()
	for _, v := range sysBindMounts {
		relPath := strings.TrimPrefix(v, "/sys")

		newelem := &domain.MountSyscallPayload{
			domain.NSenterMsgHeader{},
			domain.Mount{
				Source: v,
				Target: filepath.Join(m.Target, relPath),
				FsType: "",
				Flags:  unix.MS_BIND,
				Data:   "",
			},
		}
		payload = append(payload, newelem)
	}

	// If "/sys" is to be mounted as read-only, we want this requirement to
	// extend to all of its inner bind-mounts.
	if m.Flags&unix.MS_RDONLY == unix.MS_RDONLY {

		for _, v := range sysBindMounts {
			relPath := strings.TrimPrefix(v, "/sys")

			newelem := &domain.MountSyscallPayload{
				domain.NSenterMsgHeader{},
				domain.Mount{
					Source: "",
					Target: filepath.Join(m.Target, relPath),
					FsType: "",
					// TODO: Avoid hard-coding these flags.
					Flags: unix.MS_RDONLY | unix.MS_BIND | unix.MS_REMOUNT | unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC,
					Data:  "",
				},
			}
			payload = append(payload, newelem)
		}
	}

	return &payload
}

// Method handles overlayfs mount syscall requests.
func (m *mountSyscallInfo) processOverlayMount(
	mip domain.MountInfoParserIface) (*sysResponse, error) {

	logrus.Debugf("Processing new overlayfs mount: %v", m)

	// Notice that, in chroot scenarios, we are undoing the previous call to
	// targetAdjust() to avoid the need to mess around with the paths in the
	// 'data' object. Once within the 'nsenter' context, we will adjust all
	// path elements by doing a chroot() as part of the personality-adjustment
	// logic.
	m.targetUnadjust()

	// Create instructions payload.
	payload := m.createOverlayMountPayload(mip)
	if payload == nil {
		return nil, fmt.Errorf("Could not construct overlayMount payload")
	}

	// Create nsenter-event envelope.
	nss := m.tracer.service.nss
	event := nss.NewEvent(
		m.syscallCtx.pid,
		m.syscallCtx.uid,
		m.syscallCtx.gid,
		&domain.AllNSsButUser,
		0,
		&domain.NSenterMessage{
			Type:    domain.MountSyscallRequest,
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
		resp := m.tracer.createErrorResponse(
			m.reqId,
			responseMsg.Payload.(fuse.IOerror).Code)
		return resp, nil
	}

	return m.tracer.createSuccessResponse(m.reqId), nil
}

// Build instructions payload required for overlay-mount operations.
func (m *mountSyscallInfo) createOverlayMountPayload(
	mip domain.MountInfoParserIface) *[]*domain.MountSyscallPayload {

	var payload []*domain.MountSyscallPayload

	// Create a process struct to represent the process generating the 'mount'
	// instruction, and extract its capabilities to hand them out to 'nsenter'
	// logic.
	process := m.tracer.service.prs.ProcessCreate(m.pid, 0, 0)

	// Payload instruction for overlayfs mount request.
	payload = append(payload, m.MountSyscallPayload)

	// Insert appended fields.
	payload[0].Header = domain.NSenterMsgHeader{
		Root:         m.root,
		Cwd:          m.cwd,
		Capabilities: process.GetEffCaps(),
	}

	return &payload
}

// Method handles "nfs" mount syscall requests. Sysbox-fs does not manage nfs
// mounts per-se, but only "proxies" the nfs mount syscall. It does this in
// order to enable nfs to be mounted from within a (non init) user-ns.
func (m *mountSyscallInfo) processNfsMount(
	mip domain.MountInfoParserIface) (*sysResponse, error) {

	logrus.Debugf("Processing new nfs mount: %v", m)

	// Create instruction's payload.
	payload := m.createNfsMountPayload(mip)
	if payload == nil {
		return nil, fmt.Errorf("Could not construct nfsMount payload")
	}

	// Create nsenter-event envelope
	nss := m.tracer.service.nss
	event := nss.NewEvent(
		m.syscallCtx.pid,
		m.syscallCtx.uid,
		m.syscallCtx.gid,
		&domain.AllNSsButUser,
		0,
		&domain.NSenterMessage{
			Type:    domain.MountSyscallRequest,
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
		resp := m.tracer.createErrorResponse(
			m.reqId,
			responseMsg.Payload.(fuse.IOerror).Code)
		return resp, nil
	}

	return m.tracer.createSuccessResponse(m.reqId), nil
}

// Build instructions payload required for remount operations.
func (m *mountSyscallInfo) createNfsMountPayload(
	mip domain.MountInfoParserIface) *[]*domain.MountSyscallPayload {

	var payload []*domain.MountSyscallPayload

	// Payload instruction for re-mount request.
	payload = append(payload, m.MountSyscallPayload)

	return &payload
}

// remountAllowed purpose is to prevent certain remount operations from
// succeeding, such as preventing RO mountpoints to be remounted as RW.
//
// Method will return 'true' when the remount operation is deemed legit, and
// will return 'false' otherwise.
func (m *mountSyscallInfo) remountAllowed(
	mip domain.MountInfoParserIface) (bool, *sysResponse) {

	mh := m.tracer.service.mts.MountHelper()

	// Skip verification process if explicitly requested by the user. By default,
	// remount operations of RO immutables are not allowed.
	if m.tracer.service.allowImmutableRemounts {
		return true, nil
	}

	// Skip instructions targeting file-systems explicitly handled by sysbox-fs.
	if m.FsType == "proc" || m.FsType == "sysfs" {
		return true, nil
	}

	// Allow operation if it attempts to remount target as read-only.
	if mh.IsReadOnlyMount(m.Flags) {
		return true, nil
	}

	// There must be mountinfo state present for this target. Otherwise, return
	// error back to the user.
	info := mip.GetInfo(m.Target)
	if info == nil {
		return false, m.tracer.createErrorResponse(m.reqId, syscall.EINVAL)
	}

	// Allow operation if the remount target is a read-write mountpoint.
	if !mip.IsRoMount(info) {
		return true, nil
	}

	//
	// The following scenarios are relevant within the context of this function
	// and will be handled separately to ease the logic comprehension and its
	// maintenability / debuggability.
	//
	// The different columns in this table denote the 'context' in which the
	// remount process is executing, and thereby, dictates the logic chosen
	// to handle each remount request.
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

	// Identify the mount-ns of the process launching the remount to compare it
	// with the one of the sys container's initpid. In the unlikely case of an
	// error, let the kernel deal with it.
	processMountNs, err := m.processInfo.MountNsInode()
	if err != nil {
		return false, m.tracer.createErrorResponse(m.reqId, syscall.EINVAL)
	}
	initProcMountNs, err := m.cntr.InitProc().MountNsInode()
	if err != nil {
		return false, m.tracer.createErrorResponse(m.reqId, syscall.EINVAL)
	}

	// Obtain the sys-container's root-path inode.
	syscntrRootInode := m.cntr.InitProc().RootInode()

	// If process' mount-ns matches the sys-container's one, then we can simply
	// rely on the target's mountID to discern an immutable target from a
	// regular one. Otherwise, we cannot rely on the mountID field, as the values
	// allocated by kernel for these very mountpoints will differ in other mount
	// namespaces.
	if processMountNs == initProcMountNs {

		var (
			immutable          bool
			bindmountImmutable bool
		)

		if ok := m.cntr.IsImmutableRoMountID(info.MountID); ok {
			logrus.Infof("Rejected remount operation over read-only immutable target: %s",
				m.Target)
			immutable = true
		}

		if !immutable {
			if ok := m.cntr.IsImmutableRoBindMount(info); ok {
				logrus.Infof("Rejected remount operation over bind-mount to read-only immutable target: %s",
					m.Target)
				bindmountImmutable = true
			}
		}

		if !immutable && !bindmountImmutable {
			return true, nil
		}

		if logrus.IsLevelEnabled(logrus.DebugLevel) {
			if m.processInfo.Root() == "/" {
				processRootInode := m.processInfo.RootInode()

				// Scenario 1): no-unshare(mnt) & no-privot() & no-chroot()
				if processRootInode == syscntrRootInode {
					logrus.Debug("Rejected remount operation -- scenario 1")
				}

				// Scenario 2): no-unshare(mnt) & pivot() & no-chroot()
				if processRootInode != syscntrRootInode {
					logrus.Debug("Rejected remount operation -- scenario 2")
				}
			}

			if m.processInfo.Root() != "/" {
				// We are dealing with a chroot'ed process, so obtain the inode of "/"
				// as seen within the process' namespaces, and *not* the one associated
				// to the process' root-path.
				processRootInode, err := mip.ExtractInode("/")
				if err != nil {
					return false, m.tracer.createErrorResponse(m.reqId, syscall.EINVAL)
				}

				// Scenario 3): no-unshare(mnt) & no-pivot() & chroot()
				if processRootInode == syscntrRootInode {
					logrus.Debug("Rejected remount operation -- scenario 3")
				}

				// Scenario 4): no-unshare(mnt) & pivot() & chroot()
				if processRootInode != syscntrRootInode {
					logrus.Debug("Rejected remount operation -- scenario 4")
				}
			}
		}

		return false, m.tracer.createErrorResponse(m.reqId, syscall.EPERM)

	} else {

		if m.processInfo.Root() == "/" {
			processRootInode := m.processInfo.RootInode()

			// Scenario 5): unshare(mnt) & no-pivot() & no-chroot()
			if processRootInode == syscntrRootInode {

				// We need to check if we're dealing with an overlapped mount, as
				// this is a case that we usually (see exception below) want to
				// allow.
				if mip.IsOverlapMount(info) {
					// The exception mentioned above refer to the scenario where
					// the overlapped mountpoint is an immutable itself, hence the
					// checkpoint below.
					if m.cntr.IsImmutableOverlapMountpoint(info.MountPoint) {
						logrus.Infof("Rejected remount operation over immutable overlapped target: %s (scenario 5)",
							m.Target)
						return false, m.tracer.createErrorResponse(m.reqId, syscall.EPERM)
					}
					return true, nil
				}

				// In this scenario we have full access to all the mountpoints
				// within the sys-container (different mount-id though), so we
				// can safely rely on their mountinfo attributes to determine
				// resource's immutability.
				if m.cntr.IsImmutableRoMountpoint(info.MountPoint) {
					logrus.Infof("Rejected remount operation over read-only immutable target: %s (scenario 5)",
						m.Target)
					return false, m.tracer.createErrorResponse(m.reqId, syscall.EPERM)
				}

				if ok := m.cntr.IsImmutableRoBindMount(info); ok {
					logrus.Infof("Rejected remount operation over bind-mount to read-only immutable target: %s (scenario 5)",
						m.Target)
					return false, m.tracer.createErrorResponse(m.reqId, syscall.EPERM)
				}

				return true, nil
			}

			// Scenario 6): unshare(mnt) & pivot() & no-chroot()
			if processRootInode != syscntrRootInode {
				isImmutable, err := m.cntr.IsImmutableRoMount(info)
				if err != nil {
					return false, m.tracer.createErrorResponse(m.reqId, syscall.EINVAL)
				}
				if isImmutable {
					logrus.Infof("Rejected remount operation over read-only immutable target: %s (scenario 6)",
						m.Target)
					return false, m.tracer.createErrorResponse(m.reqId, syscall.EPERM)
				}

				if ok := m.cntr.IsImmutableRoBindMount(info); ok {
					logrus.Infof("Rejected remount operation over bind-mount to read-only-immutable target: %s (scenario 6)",
						m.Target)
					return false, m.tracer.createErrorResponse(m.reqId, syscall.EPERM)
				}

				return true, nil
			}
		}

		if m.processInfo.Root() != "/" {
			// We are dealing with a chroot'ed process, so obtain the inode of "/"
			// as seen within the process' namespaces, and *not* the one associated
			// to the process' root-path.
			processRootInode, err := mip.ExtractInode("/")
			if err != nil {
				return false, m.tracer.createErrorResponse(m.reqId, syscall.EINVAL)
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
					if m.cntr.IsImmutableOverlapMountpoint(info.MountPoint) {
						logrus.Infof("Rejected remount operation over immutable overlapped target: %s (scenario 7)",
							m.Target)
						return false, m.tracer.createErrorResponse(m.reqId, syscall.EPERM)
					}
					return true, nil
				}

				// In this scenario we have full access to all the mountpoints
				// within the sys-container (different mount-id though), so we
				// can safely rely on their mountinfo attributes to determine
				// resource's immutability.
				if m.cntr.IsImmutableRoMountpoint(info.MountPoint) {
					logrus.Infof("Rejected remount operation over read-only immutable target: %s (scenario 7)",
						m.Target)
					return false, m.tracer.createErrorResponse(m.reqId, syscall.EPERM)
				}

				if ok := m.cntr.IsImmutableRoBindMount(info); ok {
					logrus.Infof("Rejected remount operation over bind-mount to read-only immutable target: %s (scenario 7)",
						m.Target)
					return false, m.tracer.createErrorResponse(m.reqId, syscall.EPERM)
				}

				return true, nil
			}

			// Scenario 8): unshare(mnt) & pivot() & chroot()
			if processRootInode != syscntrRootInode {
				isImmutable, err := m.cntr.IsImmutableRoMount(info)
				if err != nil {
					return false, m.tracer.createErrorResponse(m.reqId, syscall.EINVAL)
				}
				if isImmutable {
					logrus.Infof("Rejected remount operation over read-only immutable target: %s (scenario 8)",
						m.Target)
					return false, m.tracer.createErrorResponse(m.reqId, syscall.EPERM)
				}

				if ok := m.cntr.IsImmutableRoBindMount(info); ok {
					logrus.Infof("Rejected remount operation over bind-mount to read-only immutable target: %s (scenario 8)",
						m.Target)
					return false, m.tracer.createErrorResponse(m.reqId, syscall.EPERM)
				}

				return true, nil
			}
		}
	}

	return true, nil
}

func (m *mountSyscallInfo) processRemount(
	mip domain.MountInfoParserIface) (*sysResponse, error) {

	logrus.Debugf("Processing re-mount: %v", m)

	// Create instruction's payload.
	payload := m.createRemountPayload(mip)
	if payload == nil {
		return nil, fmt.Errorf("Could not construct ReMount payload")
	}

	// Create nsenter-event envelope.
	nss := m.tracer.service.nss
	event := nss.NewEvent(
		m.syscallCtx.pid,
		m.syscallCtx.uid,
		m.syscallCtx.gid,
		&domain.AllNSsButUser,
		0,
		&domain.NSenterMessage{
			Type:    domain.MountSyscallRequest,
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
		resp := m.tracer.createErrorResponse(
			m.reqId,
			responseMsg.Payload.(fuse.IOerror).Code)
		return resp, nil
	}

	return m.tracer.createSuccessResponse(m.reqId), nil
}

// Build instructions payload required for remount operations.
func (m *mountSyscallInfo) createRemountPayload(
	mip domain.MountInfoParserIface) *[]*domain.MountSyscallPayload {

	var payload []*domain.MountSyscallPayload

	mh := m.tracer.service.mts.MountHelper()

	// A procfs mount inside a sys container is a combination of a base proc
	// mount plus sysbox-fs submounts. If the remount is done on the base mount,
	// its effect is also applied to the submounts. If the remount is on a
	// submount, its effect is limited to that submount.

	submounts := []string{}

	if mip.IsSysboxfsBaseMount(m.Target) {
		submounts = mip.GetSysboxfsSubMounts(m.Target)
	} else {
		submounts = append(submounts, m.Target)
	}

	for _, subm := range submounts {
		submInfo := mip.GetInfo(subm)

		perMountFlags := mh.StringToFlags(submInfo.Options)
		perFsFlags := mh.StringToFlags(submInfo.VfsOptions)
		submFlags := perMountFlags | perFsFlags

		// Pass the remount flags to the submounts
		submFlags |= unix.MS_REMOUNT

		// The submounts must always be remounted with "MS_BIND" to ensure that
		// only the submounts are affected. Otherwise, the remount effect
		// applies at the sysbox-fs fuse level, causing weird behavior (e.g.,
		// remounting /proc as read-only would cause all sysbox-fs managed
		// submounts under /sys to become read-only too!).
		submFlags |= unix.MS_BIND

		// We only propagate changes to the MS_RDONLY flag to the submounts. In
		// the future we could propagate other flags too.
		//
		// For MS_RDONLY:
		//
		// When set, we apply the read-only flag on all submounts. When cleared,
		// we apply the read-write flag on all submounts which are not mounted
		// as read-only in the container's /proc.

		if m.Flags&unix.MS_RDONLY == unix.MS_RDONLY {
			submFlags |= unix.MS_RDONLY
		} else {
			if !mip.IsSysboxfsRoSubmount(subm) {
				submFlags = submFlags &^ unix.MS_RDONLY
			}
		}

		// Leave the filesystem options (aka data) unchanged; note that since
		// mountinfo provides them mixed with flags, we must filter the options
		// out.
		submOpts := mh.FilterFsFlags(submInfo.VfsOptions)

		newelem := &domain.MountSyscallPayload{
			domain.NSenterMsgHeader{},
			domain.Mount{
				Source: "",
				Target: subm,
				FsType: "",
				Flags:  submFlags,
				Data:   submOpts,
			},
		}
		payload = append(payload, newelem)
	}

	if mip.IsSysboxfsBaseMount(m.Target) {
		payload = append(payload, m.MountSyscallPayload)
	}

	return &payload
}

// Method handles bind-mount requests whose source is a mountpoint managed by
// sysbox-fs.
func (m *mountSyscallInfo) processBindMount(
	mip domain.MountInfoParserIface) (*sysResponse, error) {

	logrus.Debugf("Processing bind mount: %v", m)

	// Create instruction's payload.
	payload := m.createBindMountPayload(mip)
	if payload == nil {
		return nil, fmt.Errorf("Could not construct ReMount payload")
	}

	// Create nsenter-event envelope.
	nss := m.tracer.service.nss
	event := nss.NewEvent(
		m.syscallCtx.pid,
		m.syscallCtx.uid,
		m.syscallCtx.gid,
		&domain.AllNSs,
		0,
		&domain.NSenterMessage{
			Type:    domain.MountSyscallRequest,
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
		resp := m.tracer.createErrorResponse(
			m.reqId,
			responseMsg.Payload.(fuse.IOerror).Code)
		return resp, nil
	}

	return m.tracer.createSuccessResponse(m.reqId), nil
}

// Build instructions payload required for bind-mount operations.
func (m *mountSyscallInfo) createBindMountPayload(
	mip domain.MountInfoParserIface) *[]*domain.MountSyscallPayload {

	var payload []*domain.MountSyscallPayload

	// A procfs mount inside a sys container is a combination of a base proc
	// mount plus sysbox-fs submounts. If the bind-mount is done on the base
	// mount, its effect is also applied to the submounts.

	payload = append(payload, m.MountSyscallPayload)

	// If the bind-mount is recursive, then the kernel will do the remounting
	// of the submounts. No need for us to do anything.
	if m.Flags&unix.MS_REC == unix.MS_REC {
		return &payload
	}

	// If the bind-mount is not recursive, then we do the bind-mount of the
	// sysbox-fs managed submounts explicitly.
	submounts := mip.GetSysboxfsSubMounts(m.Source)

	for _, subm := range submounts {
		relTarget := strings.TrimPrefix(subm, m.Source)
		subTarget := filepath.Join(m.Target, relTarget)

		newelem := &domain.MountSyscallPayload{
			domain.NSenterMsgHeader{},
			domain.Mount{
				Source: subm,
				Target: subTarget,
				FsType: "",
				Flags:  m.Flags,
				Data:   "",
			},
		}
		payload = append(payload, newelem)
	}

	return &payload
}

// Method addresses scenarios where the process generating the mount syscall has
// a 'root' attribute different than default one ("/"). This is typically the
// case in chroot'ed environments. Method's goal is to make the required target
// adjustments so that sysbox-fs can carry out the mount in the expected context.
func (m *mountSyscallInfo) targetAdjust() {

	root := m.syscallCtx.root

	if root == "/" {
		return
	}

	m.Target = filepath.Join(root, m.Target)
}

// Undo targetAdjust()
func (m *mountSyscallInfo) targetUnadjust() {

	root := m.syscallCtx.root

	if root == "/" {
		return
	}

	m.Target = strings.TrimPrefix(m.Target, m.root)
}

func (m *mountSyscallInfo) String() string {
	return fmt.Sprintf("source: %s, target: %s, fstype: %s, flags: %#x, data: %s, root: %s, cwd: %s",
		m.Source, m.Target, m.FsType, m.Flags, m.Data, m.root, m.cwd)
}
