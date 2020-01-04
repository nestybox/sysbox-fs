package seccomp

import (
	"github.com/nestybox/sysbox-fs/domain"
	"golang.org/x/sys/unix"
	_"github.com/sirupsen/logrus"
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

// MountSyscall processing wrapper instruction. Not utilized at this time.
func (s *mountSyscallInfo) process() error {
	return nil
}

// Method handles '/proc' mount syscall requests.
func (s *mountSyscallInfo) processProcMount() error {

	// Create nsenterEvent to initiate interaction with container namespaces.
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
			Payload: s.MountSyscallPayload,
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

	// Prepare "/proc/sys" bind-mount operation.
	procsysMount := &mountSyscallInfo{
		MountSyscallPayload: &domain.MountSyscallPayload{
			Source: "/proc/sys",
			Target: s.Target + "/sys",
			FsType: "",
			Flags: unix.MS_BIND | unix.MS_REC,
			Data:   "",
		},
	}

	// Reusing previous event envelope to send new mount operation.
	event.SetRequestMsg(
		&domain.NSenterMessage{
			Type: domain.MountSyscallRequest,
			Payload: procsysMount,
		},
	)

	// Launch nsenter-event.
	err = nss.SendRequestEvent(event)
	if err != nil {
		return err
	}

	// Obtain nsenter-event response.
	responseMsg = nss.ReceiveResponseEvent(event)
	if responseMsg.Type == domain.ErrorResponse {
		return responseMsg.Payload.(error)
	}

	return nil
}

// Method handles '/proc/sys' (re)mount syscall requests.
func (s *mountSyscallInfo) processProcSysMount() error {

    // Adjust mount-flags to match sysboxfs default flags.
    s.Flags |= sysboxfsDefaultMountFlags

    // Create nsenterEvent to initiate interaction with container namespaces.
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
            Payload: s.MountSyscallPayload,
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
