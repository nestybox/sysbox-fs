package seccomp

import (
	"github.com/nestybox/sysbox-fs/domain"
	"golang.org/x/sys/unix"
	_"github.com/sirupsen/logrus"
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
const sysboxfsDefaultMountFlags =
	unix.MS_BIND | unix.MS_REC | unix.MS_NODEV | unix.MS_NOSUID | unix.MS_RELATIME

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
	err := nss.RequestEvent(event)
	if err != nil {
		return err
	}

	// Obtain nsenter-event response.
	responseMsg := nss.ResponseEvent(event)
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

	event = nss.NewEvent(
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
			Payload: procsysMount.MountSyscallPayload,
		},
		nil,
	)

	// Launch nsenter-event.
	err = nss.RequestEvent(event)
	if err != nil {
		return err
	}

	// Obtain nsenter-event response.
	responseMsg = nss.ResponseEvent(event)
	if responseMsg.Type == domain.ErrorResponse {
		return responseMsg.Payload.(error)
	}

	return nil
}
