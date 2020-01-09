package seccomp

import (
	"fmt"
	"strconv"
	"syscall"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// Default set of mount-flags utilized to mount /var/lib/sysboxfs into sysbox's
// system containers. This default set must be taken into account at the time
// procfs nodes are bind-mounted into L2 app-containers, as the flags to utilize
// for each node must match the ones utilized within L1 sys containers.
//
// TODO: Note that these flags are not chosen by sysbox-fs nor Bazil's FUSE
// library implementations, so they are subject to change in subsequent kernel
// upgrades. Therefore, our implementation should ideally extract these flags
// from each system (e.g. by parsing /proc/mounts) to avoid hard-coding their
// values as we are doing below.
const sysboxfsDefaultMountFlags = unix.MS_NODEV | unix.MS_NOSUID | unix.MS_RELATIME

const bindMountFlags = unix.MS_BIND | unix.MS_REC

const sysboxfsBindMountFlags = bindMountFlags | sysboxfsDefaultMountFlags

const sysboxfsRemountFlags = unix.MS_REMOUNT | sysboxfsBindMountFlags

const sysboxfsReadOnlyRemountFlags = unix.MS_RDONLY | sysboxfsRemountFlags

// Set of mount-flags to skip during mount syscall processing. Notice that with
// the exception of MS_BIND and MS_REMOUNT, all these flags are associated to
// operations that modify existing mount-points, which corresponds to actions
// that the kernel (and not sysboxfs) should execute.
const sysboxSkipMountFlags = unix.MS_SHARED | unix.MS_PRIVATE | unix.MS_SLAVE | unix.MS_UNBINDABLE | unix.MS_MOVE

// Syscall generic information.
type syscallInfo struct {
	syscallNum int32          // Value representing the syscall
	reqId      uint64         // Id associated to the syscall request
	pid        uint32         // Pid of the process generating the syscall
	tracer     *syscallTracer // Backpointer to the seccomp-tracer owning the syscall
}

// MountSyscall information structure.
type mountSyscallInfo struct {
	syscallInfo                 // syscall generic info
	*domain.MountSyscallPayload // mount-syscall specific details
}

// MountSyscall processing wrapper instruction.
func (s *mountSyscallInfo) process() (*sysResponse, error) {

	switch s.Source {

	case "proc":
		return s.processProcMount()

	case "sysfs":
		return s.processSysMount()

	case "/proc/sys":
		// Process incoming "/proc/sys" remount instructions. Disregard
		// "/proc/sys" pure bind operations (no new flag settings) as we
		// are already taking care of that as part of "/proc" new mount
		// requests.
		if s.Flags&^sysboxfsBindMountFlags == 0 {
			return s.tracer.createSuccessResponse(s.reqId), nil
		}
		return s.processProcSysMount()

	default:
		logrus.Errorf("Unsupported mount request received: %v", s.string())
	}

	return nil, fmt.Errorf("Unsupported mount syscall request")
}

// Method handles "/proc" mount syscall requests. As part of this function, we
// also bind-mount all the sysbox-fs' emulated resources into the mount target
// requested by the user. Our goal here is to extend sysbox-fs' virtualization
// capabilities to L2 app containers and/or L1 chroot'ed environments.
func (s *mountSyscallInfo) processProcMount() (*sysResponse, error) {

	payload := s.createProcMountPayload()

	// Create nsenter-event envelope.
	nss := s.tracer.sms.nss
	event := nss.NewEvent(
		s.syscallInfo.pid,
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
		resp := s.tracer.createErrorResponse(
			s.reqId,
			responseMsg.Payload.(error).(syscall.Errno))

		return resp, nil
	}

	return s.tracer.createSuccessResponse(s.reqId), nil
}

// Method handles '/proc/sys' (re)mount syscall requests.
func (s *mountSyscallInfo) processProcSysMount() (*sysResponse, error) {

	// Adjust mount-flags to incorporate sysboxfs default flags.
	s.Flags |= sysboxfsBindMountFlags

	// Create nsenter-event envelope.
	nss := s.tracer.sms.nss
	event := nss.NewEvent(
		s.syscallInfo.pid,
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
			Payload: []*domain.MountSyscallPayload{s.MountSyscallPayload},
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
		resp := s.tracer.createErrorResponse(
			s.reqId,
			responseMsg.Payload.(error).(syscall.Errno))

		return resp, nil
	}

	return s.tracer.createSuccessResponse(s.reqId), nil
}

// Method handles "/sys" mount syscall requests. As part of this function, we
// also bind-mount all the sysbox-fs' emulated resources into the mount target
// requested by the user.
func (s *mountSyscallInfo) processSysMount() (*sysResponse, error) {

	var payload = []*domain.MountSyscallPayload{

		// Mount operation: "/sys" -> "target/sys"
		s.MountSyscallPayload,

		// Bind-mount operation: "*/parameters/hashsize" -> "target/*/parameter/hashsize"
		&domain.MountSyscallPayload{
			Source: "/sys/module/nf_conntrack/parameters/hashsize",
			Target: s.Target + "/module/nf_conntrack/parameters/hashsize",
			FsType: "",
			Flags:  sysboxfsBindMountFlags,
			Data:   "",
		},
	}

	// Create nsenter-event envelope.
	nss := s.tracer.sms.nss
	event := nss.NewEvent(
		s.syscallInfo.pid,
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
		resp := s.tracer.createErrorResponse(
			s.reqId,
			responseMsg.Payload.(error).(syscall.Errno))

		return resp, nil
	}

	return s.tracer.createSuccessResponse(s.reqId), nil
}

func (s *mountSyscallInfo) createProcMountPayload() []*domain.MountSyscallPayload {

	var payload = []*domain.MountSyscallPayload{

		// Mount operation: "/proc" -> "target/proc"
		s.MountSyscallPayload,

		// Bind-mount operation: "/proc/sys" -> "target/proc/sys"
		&domain.MountSyscallPayload{
			Source: "/proc/sys",
			Target: s.Target + "/sys",
			FsType: "",
			Flags:  bindMountFlags,
			Data:   "",
		},

		// Bind-mount operation: "/proc/uptime" -> "target/proc/uptime"
		&domain.MountSyscallPayload{
			Source: "/proc/uptime",
			Target: s.Target + "/uptime",
			FsType: "",
			Flags:  bindMountFlags,
			Data:   "",
		},

		// Bind-mount operation: "/proc/swaps" -> "target/proc/swaps"
		&domain.MountSyscallPayload{
			Source: "/proc/swaps",
			Target: s.Target + "/swaps",
			FsType: "",
			Flags:  bindMountFlags,
			Data:   "",
		},
	}

	// If necessary extend readonly mode to procfs bind-mounts.
	if s.Flags&^unix.MS_RDONLY == s.Flags {
		return payload
	}

	var payload_remount = []*domain.MountSyscallPayload{

		// Re-mount operation: "/proc/sys" -> "/proc/sys" (RO)
		&domain.MountSyscallPayload{
			Source: "",
			Target: s.Target + "/sys",
			FsType: "",
			Flags:  sysboxfsReadOnlyRemountFlags,
			Data:   "",
		},

		// Re-mount operation: "/proc/uptime" -> "/proc/uptime" (RO)
		&domain.MountSyscallPayload{
			Source: "",
			Target: s.Target + "/uptime",
			FsType: "",
			Flags:  sysboxfsReadOnlyRemountFlags,
			Data:   "",
		},

		// Re-mount operation: "/proc/swaps" -> "/proc/swaps" (RO)
		&domain.MountSyscallPayload{
			Source: "",
			Target: s.Target + "/swaps",
			FsType: "",
			Flags:  sysboxfsReadOnlyRemountFlags,
			Data:   "",
		},
	}

	for _, p := range payload_remount {
		payload = append(payload, p)
	}

	return payload
}

func (s *mountSyscallInfo) string() string {

	result := "source: " + s.Source + " target: " + s.Target +
		" fstype: " + s.FsType + " flags: " +
		strconv.FormatUint(s.Flags, 10)

	return result
}
