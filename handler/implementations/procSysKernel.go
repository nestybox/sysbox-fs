//
// Copyright 2019-2023 Nestybox, Inc.
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
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
)

//
// /proc/sys/kernel handler
//
// Emulated resources:
//
// * /proc/sys/kernel/cap_last_cap
//
// Documentation: The value in this file exposes the numerical value of the
// highest capability supported by the running kernel ('37' as of today's
// latest / 5.X kernels ).
//
// This handler is used for performance reasons (rather than functional reasons),
// as having it avoids using the passthrough (common) handler for accesses to
// /proc/sys/kernel/cap_last_cap which is the most commonly accessed sysctl.
//
//
// * /proc/sys/kernel/sysrq
//
// Documentation: It is a ‘magical’ key combo you can hit which the kernel will
// respond to regardless of whatever else it is doing, unless it is completely
// locked up.
//
// Supported values:
//
// 0 - disable sysrq completely
//
// 1 - enable all functions of sysrq
//
// >1 - bitmask of allowed sysrq functions (see below for detailed function
// description):
//
//  2 =   0x2 - enable control of console logging level
//  4 =   0x4 - enable control of keyboard (SAK, unraw)
//  8 =   0x8 - enable debugging dumps of processes etc.
//  16 =  0x10 - enable sync command
//  32 =  0x20 - enable remount read-only
//  64 =  0x40 - enable signalling of processes (term, kill, oom-kill)
//  128 = 0x80 - allow reboot/poweroff
//  256 = 0x100 - allow nicing of all RT tasks
//
// Note: As this is a system-wide attribute, changes will be only made
// superficially (at sys-container level). IOW, the host FS value will be left
// untouched.
//
//
// * /proc/sys/kernel/panic handler
//
// Documentation: The value in this file represents the number of seconds the
// kernel waits before rebooting on a panic. The default setting is 0, which
// doesn't cause a reboot.
//
// Taking into account the semantics of the value held within this file (time
// units), and the obvious conflicts that can arise among containers / hosts
// when defining different values, in this implementation we have opted by
// allowing read/write operations within the container, but we don't push
// these values down to the host FS. IOW, the host value will be the one
// honored at panic time.
//
//
// * /proc/sys/kernel/panic_on_oops handler
//
// Documentation: The value in this file defines the kernel behavior
// when an 'oops' is encountered. The following values are supported:
//
// 0: try to continue operation (default option)
//
// 1: panic immediately.  If the 'panic' procfs node is also non-zero then the
// machine will be rebooted.
//
// Taking into account that kernel can either operate in one mode or the other,
// we cannot let the values defined within a sys container to be pushed down to
// the host FS, as that could potentially affect the overall system stability.
// IOW, the host value will be the one honored upon 'oops' arrival.
//
//
// * /proc/sys/kernel/kptr_restrict
//
// Documentation: This toggle indicates whether restrictions are placed on
// exposing kernel addresses via /proc and other interfaces.
//
// Supported values:
//
// - "0": (default) the address is hashed before printing. (This is the
// equivalent to %p.).
//
// - "1": kernel pointers printed using the %pK format specifier will be
// replaced with 0's unless the user has CAP_SYSLOG and effective user and
// group ids are equal to the real ids. This is because %pK checks are done
// at read() time rather than open() time, so if permissions are elevated
// between the open() and the read() (e.g via a setuid binary) then %pK will
// not leak kernel pointers to unprivileged users. Note, this is a temporary
// solution only. The correct long-term solution is to do the permission
// checks at open() time. Consider removing world read permissions from files
// that use %pK, and using dmesg_restrict to protect against uses of %pK in
// dmesg(8) if leaking kernel pointer values to unprivileged users is a
// concern.
//
// - "2": kernel pointers printed using %pK will be replaced with 0's
// regardless of privileges.
//
// Note: As this is a system-wide attribute with mutually-exclusive values,
// changes will be only made superficially (at sys-container level). IOW,
// the host FS value will be left untouched.
//
//
// * /proc/sys/kernel/dmesg_restrict
//
// Documentation: This toggle indicates whether unprivileged users are prevented
// from using dmesg(8) to view messages from the kernel’s log buffer. The following
// values are supported:
//
// 0: there are no restrictions
//
// 1: users must have CAP_SYSLOG to use dmesg
//
// Note: As this is a system-wide attribute with mutually-exclusive values, changes
// will be only made superficially (at sys-container level). IOW, the host FS value
// will be left untouched. As result, the value being set in this resource will have
// no impact on the output (if any) generated by 'dmesg'.
//
//
// * /proc/sys/kernel/ngroups_max handler
//
// Documentation: The numerical value stored in this file represents the maximum
// number of supplementary groups of which a process can be a member of (65k in
// kernels 2.2+). This is a system-wide number and does not appear to be
// re-configurable at runtime, so we will proceed to cache its value on a
// per-container basis.
//
// Notice that this resource is perfectly reachable within a regular or system
// container. That's to say that our main purpose here is not 'functional'; we
// we are creating this handler to enhance sysbox-fs performance: every 'sudo'
// instruction does two consecutive reads() over this resource -- and that
// entails the execution of all the other file-operations too (i.e. lookup,
// getattr, etc).
//
//
// * /proc/sys/kernel/printk handler
//
// Documentation: The four values in printk denote: console_loglevel,
// default_message_loglevel, minimum_console_loglevel and default_console_loglevel
// respectively. These values influence printk() behavior when printing or logging
// error messages.
//
// Supported values:
//
// - console_loglevel: messages with a higher priority than this will be printed
// to the console.
// - default_message_loglevel: messages without an explicit priority will be
// printed with this priority.
// - minimum_console_loglevel: minimum (highest) value to which console_loglevel
// can be set.
// - default_console_loglevel: default value for console_loglevel.
//
// Note 1: As this is a system-wide attribute with mutually-exclusive values,
// changes will be only made superficially (at sys-container level). IOW,
// the host FS value will be left untouched.
//
// Note 2: For this specific node we are not verifying that the values passed by
// the user in write() operations match the semantics and the format expected by
// the kernel. This is something that we may need to improve in the future.
// Example: "4   4 	1	7".
//
//
// * /proc/sys/kernel/pid_max (since Linux 2.5.34)
//
// Documentation: This file specifies the value at which PIDs wrap around (i.e.,
// the value in this file is one greater than the maximum PID).  PIDs greater
// than this value are not allocated; thus, the value in this file also acts as
// a system-wide limit on the total number of processes and threads.  The
// default value for this file, 32768, results in the same range of PIDs as on
// earlier kernels.  On 32-bit platforms, 32768 is the maximum value for
// pid_max.  On 64-bit systems, pid_max can be set to any value up to 2^22
// (PID_MAX_LIMIT, approximately 4 million).
//

const (
	minSysrqVal = 0
	maxSysrqVal = 511

	minKptrRestrictVal = 0
	maxKptrRestrictVal = 3

	minDmesgRestrictVal = 0
	maxDmesgRestrictVal = 1

	minPanicOopsVal = 0
	maxPanicOopsVal = 1

	minPidMaxVal = 1
	maxPidMaxVal = 4194304
)

type ProcSysKernel struct {
	domain.HandlerBase
}

var ProcSysKernel_Handler = &ProcSysKernel{
	domain.HandlerBase{
		Name:    "ProcSysKernel",
		Path:    "/proc/sys/kernel",
		Enabled: true,
		EmuResourceMap: map[string]*domain.EmuResource{
			"domainname": {
				Kind:    domain.FileEmuResource,
				Mode:    os.FileMode(uint32(0644)),
				Enabled: true,
				Size:    4096,
			},
			"hostname": {
				Kind:    domain.FileEmuResource,
				Mode:    os.FileMode(uint32(0644)),
				Enabled: true,
				Size:    4096,
			},
			"kptr_restrict": {
				Kind:    domain.FileEmuResource,
				Mode:    os.FileMode(uint32(0644)),
				Enabled: true,
				Size:    2,
			},
			"dmesg_restrict": {
				Kind:    domain.FileEmuResource,
				Mode:    os.FileMode(uint32(0644)),
				Enabled: true,
				Size:    2,
			},
			"ngroups_max": {
				Kind:    domain.FileEmuResource,
				Mode:    os.FileMode(uint32(0444)),
				Enabled: true,
				Size:    1024,
			},
			"cap_last_cap": {
				Kind:    domain.FileEmuResource,
				Mode:    os.FileMode(uint32(0444)),
				Enabled: true,
				Size:    1024,
			},
			"panic": {
				Kind:    domain.FileEmuResource,
				Mode:    os.FileMode(uint32(0644)),
				Enabled: true,
				Size:    4096,
			},
			"panic_on_oops": {
				Kind:    domain.FileEmuResource,
				Mode:    os.FileMode(uint32(0644)),
				Enabled: true,
				Size:    2,
			},
			"printk": {
				Kind:    domain.FileEmuResource,
				Mode:    os.FileMode(uint32(0644)),
				Enabled: true,
				Size:    1024,
			},
			"sysrq": {
				Kind:    domain.FileEmuResource,
				Mode:    os.FileMode(uint32(0644)),
				Enabled: true,
				Size:    1024,
			},
			"pid_max": {
				Kind:    domain.FileEmuResource,
				Mode:    os.FileMode(uint32(0644)),
				Enabled: true,
				Size:    1024,
			},
		},
	},
}

func (h *ProcSysKernel) Lookup(
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
			Fsize:    v.Size,
		}

		return info, nil
	}

	// If looked-up element hasn't been found by now, let's look into the actual
	// container rootfs.
	return h.Service.GetPassThroughHandler().Lookup(n, req)
}

func (h *ProcSysKernel) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (bool, error) {

	var resource = n.Name()

	logrus.Debugf("Executing Open() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	flags := n.OpenFlags()

	switch resource {
	case "cap_last_cap":
		if flags&syscall.O_WRONLY == syscall.O_WRONLY ||
			flags&syscall.O_RDWR == syscall.O_RDWR {
			return false, fuse.IOerror{Code: syscall.EACCES}
		}
		return false, nil

	case "pid_max":
		return false, nil

	case "ngroups_max":
		if flags&syscall.O_WRONLY == syscall.O_WRONLY ||
			flags&syscall.O_RDWR == syscall.O_RDWR {
			return false, fuse.IOerror{Code: syscall.EACCES}
		}
		return false, nil

	case "domainname":
		return false, nil

	case "hostname":
		return false, nil

	case "kptr_restrict":
		return false, nil

	case "dmesg_restrict":
		return false, nil

	case "panic":
		return false, nil

	case "panic_on_oops":
		return false, nil

	case "sysrq":
		return false, nil

	case "printk":
		return false, nil

	case "shmall":
		fallthrough
	case "shmmax":
		fallthrough
	case "shmmni":
		return h.Service.GetPassThroughHandler().OpenWithNS(n, req, domain.AllNSsButUser)
	}

	// Refer to generic handler if no node match is found above.
	return h.Service.GetPassThroughHandler().Open(n, req)
}

func (h *ProcSysKernel) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	var resource = n.Name()

	logrus.Debugf("Executing Read() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	switch resource {
	case "cap_last_cap":
		return readCntrData(h, n, req)

	case "pid_max":
		return readCntrData(h, n, req)

	case "ngroups_max":
		return readCntrData(h, n, req)

	case "domainname":
		return readCntrData(h, n, req)

	case "hostname":
		return readCntrData(h, n, req)

	case "kptr_restrict":
		return readCntrData(h, n, req)

	case "dmesg_restrict":
		return readCntrData(h, n, req)

	case "panic":
		return readCntrData(h, n, req)

	case "panic_on_oops":
		return readCntrData(h, n, req)

	case "sysrq":
		return readCntrData(h, n, req)

	case "printk":
		return readCntrData(h, n, req)

	case "shmall":
		fallthrough
	case "shmmax":
		fallthrough
	case "shmmni":
		return h.Service.GetPassThroughHandler().ReadWithNS(n, req, domain.AllNSsButUser)
	}

	// Refer to generic handler if no node match is found above.
	return h.Service.GetPassThroughHandler().Read(n, req)
}

func (h *ProcSysKernel) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	var resource = n.Name()

	logrus.Debugf("Executing Write() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	switch resource {
	case "cap_last_cap":
		return 0, nil

	case "ngroups_max":
		return 0, nil

	case "pid_max":
		if !checkIntRange(req.Data, minPidMaxVal, maxPidMaxVal) {
			return 0, fuse.IOerror{Code: syscall.EINVAL}
		}
		return writeCntrData(h, n, req, nil)

	case "panic":
		return writeCntrData(h, n, req, nil)

	case "printk":
		return writeCntrData(h, n, req, nil)

	case "panic_on_oops":
		// Even though only values 0 and 1 are defined for panic_on_oops, the
		// kernel allows other values to be written; thus no range check is
		// performed here.
		return writeCntrData(h, n, req, nil)

	case "kptr_restrict":
		if !checkIntRange(req.Data, minKptrRestrictVal, maxKptrRestrictVal) {
			return 0, fuse.IOerror{Code: syscall.EINVAL}
		}
		return writeCntrData(h, n, req, nil)

	case "dmesg_restrict":
		if !checkIntRange(req.Data, minDmesgRestrictVal, maxDmesgRestrictVal) {
			return 0, fuse.IOerror{Code: syscall.EINVAL}
		}
		return writeCntrData(h, n, req, nil)

	case "sysrq":
		if !checkIntRange(req.Data, minSysrqVal, maxSysrqVal) {
			return 0, fuse.IOerror{Code: syscall.EINVAL}
		}
		return writeCntrData(h, n, req, nil)

	case "domainname":
		return writeCntrData(h, n, req, nil)

	case "hostname":
		return writeCntrData(h, n, req, nil)

	case "shmall":
		fallthrough
	case "shmmax":
		fallthrough
	case "shmmni":
		// The kernel only allows true root to write to /proc/sys/kernel/shm*.
		// Root in the container's user-namespaces is not allowed to modify these
		// values, even though they are namespaced via the IPC namespace.
		// Therefore ask the passhthrough handler to enter all namespaces except
		// the user-ns, as otherwise we get permission denied.
		return h.Service.GetPassThroughHandler().WriteWithNS(n, req, domain.AllNSsButUser)
	}

	// Refer to generic handler if no node match is found above.
	return h.Service.GetPassThroughHandler().Write(n, req)
}

func (h *ProcSysKernel) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	logrus.Debugf("Executing ReadDirAll() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	// Return all entries as seen within container's namespaces.
	return h.Service.GetPassThroughHandler().ReadDirAll(n, req)
}

func (h *ProcSysKernel) ReadLink(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (string, error) {

	logrus.Debugf("Executing ReadLink() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	return h.Service.GetPassThroughHandler().ReadLink(n, req)
}

func (h *ProcSysKernel) GetName() string {
	return h.Name
}

func (h *ProcSysKernel) GetPath() string {
	return h.Path
}

func (h *ProcSysKernel) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *ProcSysKernel) GetEnabled() bool {
	return h.Enabled
}

func (h *ProcSysKernel) SetEnabled(b bool) {
	h.Enabled = b
}

func (h *ProcSysKernel) GetResourcesList() []string {

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

func (h *ProcSysKernel) GetResourceMutex(n domain.IOnodeIface) *sync.Mutex {
	resource, ok := h.EmuResourceMap[n.Name()]
	if !ok {
		return nil
	}

	return &resource.Mutex
}

func (h *ProcSysKernel) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
