package seccomp

import (
	"fmt"
	"strconv"

	"github.com/nestybox/sysbox-fs/domain"
	"golang.org/x/sys/unix"
	"github.com/sirupsen/logrus"
)

// Syscall returned actions
type syscallResponse uint

const (
	SYSCALL_INVALID syscallResponse = iota
	SYSCALL_SUCCESS
	SYSCALL_CONTINUE
	SYSCALL_ERROR
)

// Syscall generic information.
type syscallInfo struct {
	syscallNum int32           // Value/id representing the syscall
	pid        uint32          // Pid of the process generating the syscall
	tracer     *syscallTracer  // Backpointer to the seccomp-tracer owning the syscall
}

// MountSyscall information structure.
type mountSyscallInfo struct {
	syscallInfo                 // syscall generic info
	*domain.MountSyscallPayload // mount-syscall specific details
}

// MountSyscall processing wrapper instruction.
func (s *mountSyscallInfo) process() (syscallResponse, error) {

	switch s.Source {

	case "proc":
        if err := s.processProcMount(); err != nil {
            return SYSCALL_ERROR, nil
		}

	case "sysfs":
        if err := s.processSysMount(); err != nil {
            return SYSCALL_ERROR, nil
        }

	case "/proc/sys":
		// Process incoming "/proc/sys" remount instructions. Disregard
		// "/proc/sys" pure bind operations (no new flag settings) as we
		// are already taking care of that as part of "/proc" new mount
		// requests.
		if s.Flags &^ sysboxfsDefaultMountFlags == 0 {
			break
		}

		if err := s.processProcSysMount(); err != nil {
			return SYSCALL_ERROR, nil
		}

	default:
		logrus.Errorf("Unsupported mount syscall received for mount %v.",
			s.string())
		return SYSCALL_INVALID, fmt.Errorf("Unsupported mount syscall request.")
    }

	return SYSCALL_SUCCESS, nil
}

// Method handles "/proc" mount syscall requests. As part of this function, we
// also bind-mount all the sysbox-fs' emulated resources into the mount target
// requested by the user. Our goal here is to extend sysbox-fs' virtualization
// capabilities to L2 app containers and/or L1 chroot'ed environments.
func (s *mountSyscallInfo) processProcMount() error {

	var payload = []*domain.MountSyscallPayload{

		// Mount operation: "/proc" -> "target/proc"
		s.MountSyscallPayload,

		// Bind-mount operation: "/proc/sys" -> "target/proc/sys"
		&domain.MountSyscallPayload{
			Source: "/proc/sys",
			Target: s.Target + "/sys",
			FsType: "",
			Flags: unix.MS_BIND | unix.MS_REC,
			Data:   "",
		},

		// Bind-mount operation: "/proc/uptime" -> "target/proc/uptime"
		&domain.MountSyscallPayload{
			Source: "/proc/uptime",
			Target: s.Target + "/uptime",
			FsType: "",
			Flags: unix.MS_BIND | unix.MS_REC,
			Data:   "",
		},

		// Bind-mount operation: "/proc/swaps" -> "target/proc/swaps"
		&domain.MountSyscallPayload{
			Source: "/proc/swaps",
			Target: s.Target + "/swaps",
			FsType: "",
			Flags: unix.MS_BIND | unix.MS_REC,
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
			Type: domain.MountSyscallRequest,
			Payload: payload,
		},
		nil,
	)

	// Launch nsenter-event.
	err := nss.SendRequestEvent(event)
	if err != nil {
		return err
	}

	// Obtain nsenter-event response.
	responseMsg := nss.ReceiveResponseEvent(event)
	if responseMsg.Type == domain.ErrorResponse {
		return responseMsg.Payload.(error)
	}

	return nil
}

// Method handles '/proc/sys' (re)mount syscall requests.
func (s *mountSyscallInfo) processProcSysMount() error {

    // Adjust mount-flags to match sysboxfs default flags.
    s.Flags |= sysboxfsDefaultMountFlags

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
            Type: domain.MountSyscallRequest,
            Payload: []*domain.MountSyscallPayload{s.MountSyscallPayload},
        },
        nil,
    )

    // Launch nsenter-event.
    err := nss.SendRequestEvent(event)
    if err != nil {
        return err
    }

    // Obtain nsenter-event response.
    responseMsg := nss.ReceiveResponseEvent(event)
    if responseMsg.Type == domain.ErrorResponse {
        return responseMsg.Payload.(error)
    }

    return nil
}

// Method handles "/sys" mount syscall requests. As part of this function, we
// also bind-mount all the sysbox-fs' emulated resources into the mount target
// requested by the user.
func (s *mountSyscallInfo) processSysMount() error {

	var payload = []*domain.MountSyscallPayload{

		// Mount operation: "/sys" -> "target/sys"
		s.MountSyscallPayload,

		// Bind-mount operation: "*/parameters/hashsize" -> "target/*/parameter/hashsize"
		&domain.MountSyscallPayload{
			Source: "/sys/module/nf_conntrack/parameters/hashsize",
			Target: s.Target + "/module/nf_conntrack/parameters/hashsize",
			FsType: "",
			Flags: unix.MS_BIND | unix.MS_REC,
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
			Type: domain.MountSyscallRequest,
			Payload: payload,
		},
		nil,
	)

	// Launch nsenter-event.
	err := nss.SendRequestEvent(event)
	if err != nil {
		return err
	}

	// Obtain nsenter-event response.
	responseMsg := nss.ReceiveResponseEvent(event)
	if responseMsg.Type == domain.ErrorResponse {
		return responseMsg.Payload.(error)
	}

	return nil
}

func (s *mountSyscallInfo) string() string {

	result := "source: " + s.Source + " target: " + s.Target +
			  " fstype: " + s.FsType + " flags: " +
			  strconv.FormatUint(s.Flags, 10)

	return result
}