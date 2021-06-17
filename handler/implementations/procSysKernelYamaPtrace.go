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

package implementations

import (
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
)

//
// /proc/sys/kernel/yama handler
//
// Emulated resources:
//
// * /proc/sys/kernel/yama/ptrace_scope
//
// Documentation: As Linux grows in popularity, it will become a larger target
// for malware. One particularly troubling weakness of the Linux process
// interfaces is that a single user is able to examine the memory and running
// state of any of their processes. For example, if one application (e.g.
// Pidgin) was compromised, it would be possible for an attacker to attach to
// other running processes (e.g. Firefox, SSH sessions, GPG agent, etc) to
// extract additional credentials and continue to expand the scope of their
// attack without resorting to user-assisted phishing.
//
// For a solution, some applications use prctl(PR_SET_DUMPABLE, ...) to
// specifically disallow such ptrace attachment (e.g. ssh-agent), but many do
// not. A more general solution is to only allow ptrace directly from a parent
// to a child process (i.e. direct "gdb EXE" and "strace EXE" still work), or
// with CAP_SYS_PTRACE (i.e. "gdb --pid=PID", and "strace -p PID" still work
// as root).
//
// In mode 1, software that has defined application-specific relationships
// between a debugging process and its inferior (crash handlers, etc),
// prctl(PR_SET_PTRACER, pid, ...) can be used. An inferior can declare which
// other process (and its descendants) are allowed to call PTRACE_ATTACH
// against it. Only one such declared debugging process can exists for
// each inferior at a time. For example, this is used by KDE, Chromium, and
// Firefox's crash handlers, and by Wine for allowing only Wine processes
// to ptrace each other. If a process wishes to entirely disable these ptrace
// restrictions, it can call prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, ...)
// so that any otherwise allowed process (even those in external pid namespaces)
// may attach.
//
// The sysctl settings (writable only with CAP_SYS_PTRACE) are:
//
// 0 - classic ptrace permissions: a process can PTRACE_ATTACH to any other
//     process running under the same uid, as long as it is dumpable (i.e.
//     did not transition uids, start privileged, or have called
//     prctl(PR_SET_DUMPABLE...) already). Similarly, PTRACE_TRACEME is
//     unchanged.
//
// 1 - restricted ptrace: a process must have a predefined relationship
//     with the inferior it wants to call PTRACE_ATTACH on. By default,
//     this relationship is that of only its descendants when the above
//     classic criteria is also met. To change the relationship, an
//     inferior can call prctl(PR_SET_PTRACER, debugger, ...) to declare
//     an allowed debugger PID to call PTRACE_ATTACH on the inferior.
//     Using PTRACE_TRACEME is unchanged.
//
// 2 - admin-only attach: only processes with CAP_SYS_PTRACE may use ptrace
//     with PTRACE_ATTACH, or through children calling PTRACE_TRACEME.
//
// 3 - no attach: no processes may use ptrace with PTRACE_ATTACH nor via
//     PTRACE_TRACEME. Once set, this sysctl value cannot be changed.
//
// Note: As this is a system-wide attribute with mutually-exclusive values,
// changes will be only made superficially (at sys-container level). IOW,
// the host FS value will be left untouched.
//

const (
	minScopeVal = 0
	maxScopeVal = 3
)

type ProcSysKernelYama struct {
	domain.HandlerBase
}

var ProcSysKernelYama_Handler = &ProcSysKernelYama{
	domain.HandlerBase{
		Name:    "ProcSysKernelYama",
		Path:    "/proc/sys/kernel/yama",
		Enabled: true,
		EmuResourceMap: map[string]*domain.EmuResource{
			"ptrace_scope": {
				Kind:    domain.FileEmuResource,
				Mode:    os.FileMode(uint32(0644)),
				Enabled: true,
			},
		},
	},
}

func (h *ProcSysKernelYama) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	var resource = n.Name()

	logrus.Debugf("Executing Lookup() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	// Return an artificial fileInfo if looked-up element matches any of the
	// emulated nodes.
	if v, ok := h.EmuResourceMap[resource]; ok {
		info := &domain.FileInfo{
			Fname:    resource,
			Fmode:    v.Mode,
			FmodTime: time.Now(),
		}

		return info, nil
	}

	// If looked-up element hasn't been found by now, let's look into the actual
	// container rootfs.
	return h.Service.GetPassThroughHandler().Lookup(n, req)
}

func (h *ProcSysKernelYama) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	return nil
}

func (h *ProcSysKernelYama) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	var resource = n.Name()

	logrus.Debugf("Executing Read() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	// We are dealing with a single integer element being read, so we can save
	// some cycles by returning right away if offset is any higher than zero.
	if req.Offset > 0 {
		return 0, io.EOF
	}

	switch resource {
	case "ptrace_scope":
		return readFileInt(h, n, req)
	}

	// Refer to generic handler if no node match is found above.
	return h.Service.GetPassThroughHandler().Read(n, req)
}

func (h *ProcSysKernelYama) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	var resource = n.Name()

	logrus.Debugf("Executing Write() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	switch resource {
	case "ptrace_scope":
		return writeFileInt(h, n, req, minScopeVal, maxScopeVal, false)
	}

	// Refer to generic handler if no node match is found above.
	return h.Service.GetPassThroughHandler().Write(n, req)
}

func (h *ProcSysKernelYama) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	logrus.Debugf("Executing ReadDirAll() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	// Return all entries as seen within container's namespaces.
	return h.Service.GetPassThroughHandler().ReadDirAll(n, req)
}

func (h *ProcSysKernelYama) GetName() string {
	return h.Name
}

func (h *ProcSysKernelYama) GetPath() string {
	return h.Path
}

func (h *ProcSysKernelYama) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *ProcSysKernelYama) GetEnabled() bool {
	return h.Enabled
}

func (h *ProcSysKernelYama) SetEnabled(b bool) {
	h.Enabled = b
}

func (h *ProcSysKernelYama) GetResourcesList() []string {

	var resources []string

	for resourceKey, resource := range h.EmuResourceMap {
		resource.Mutex.Lock()
		if !resource.Enabled {
			resource.Mutex.Unlock()
			continue
		}
		resource.Mutex.Unlock()

		resources = append(resources, filepath.Join(h.GetPath(), resourceKey))
	}

	return resources
}

func (h *ProcSysKernelYama) GetResourceMutex(s string) *sync.Mutex {
	resource, ok := h.EmuResourceMap[s]
	if !ok {
		return nil
	}

	return &resource.Mutex
}

func (h *ProcSysKernelYama) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
