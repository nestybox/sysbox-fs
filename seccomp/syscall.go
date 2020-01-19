package seccomp

import (
	"github.com/nestybox/sysbox-fs/domain"
)

// Syscall generic information / state.
type syscallCtx struct {
	syscallNum int32                 // Value representing the syscall
	reqId      uint64                // Id associated to the syscall request
	pid        uint32                // Pid of the process generating the syscall
	cntr       domain.ContainerIface // Container hosting the process generating the syscall
	tracer     *syscallTracer        // Backpointer to the seccomp-tracer owning the syscall
}
