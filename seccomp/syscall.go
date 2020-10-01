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
	"github.com/nestybox/sysbox-fs/domain"
)

// Syscall generic information / state.
type syscallCtx struct {
	syscallNum int32                 // Value representing the syscall
	reqId      uint64                // Id associated to the syscall request
	pid        uint32                // Pid of the process generating the syscall
	uid        uint32                // Uid of the process generating the syscall
	gid        uint32                // Gid of the process generating the syscall
	cwd        string                // Cwd of process generating the syscall
	root       string                // Root of process generating the syscall
	cntr       domain.ContainerIface // Container hosting the process generating the syscall
	tracer     *syscallTracer        // Backpointer to the seccomp-tracer owning the syscall
}
