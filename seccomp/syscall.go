package seccomp

import (
	"github.com/nestybox/sysbox-fs/domain"
)

// Syscall returned actions
type syscallResponse uint

const (
	SYSCALL_INVALID syscallResponse = iota
	SYSCALL_CONTINUE
	SYSCALL_SUCCESS
	SYSCALL_PROCESS
)

// Syscall generic information.
type syscallCtx struct {
	syscallNum int32                 // Value representing the syscall
	reqId      uint64                // Id associated to the syscall request
	pid        uint32                // Pid of the process generating the syscall
	cntr       domain.ContainerIface //
	tracer     *syscallTracer        // Backpointer to the seccomp-tracer owning the syscall
}
