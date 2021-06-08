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
	"errors"
	"fmt"
	"io"
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

//
// /proc/sys/kernel/cap_last_cap handler
//
// Documentation: The value in this file exposes the numerical value of the
// highest capability supported by the running kernel ('37' as of today's
// latest / 5.X kernels ).
//
// This handler is used for performance reasons (rather than functional reasons),
// as having it avoids using the /proc/sys common handler for accesses to
// /proc/sys/kernel/cap_last_cap which is the most commonly accessed sysctl.
//

//
// /proc/sys/kernel/sysrq
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
// /proc/sys/kernel/panic handler
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
// /proc/sys/kernel/panic_on_oops handler
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
// /proc/sys/kernel/kptr_restrict
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
// /proc/sys/kernel/ngroups_max handler
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
// /proc/sys/kernel/printk handler
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

const (
	minSysrqVal = 0
	maxSysrqVal = 511
)

const (
	minRestrictVal = 0
	maxRestrictVal = 3
)

const (
	minPanicOopsVal = 0
	maxPanicOopsVal = 1
)

type ProcSysKernel struct {
	domain.HandlerBase
}

var ProcSysKernel_Handler = &ProcSysKernel{
	domain.HandlerBase{
		Name: "ProcSysKernel",
		Path: "/proc/sys/kernel",
		EmuResourceMap: map[string]domain.EmuResource{
			"domainname":    {Kind: domain.FileEmuResource, Mode: os.FileMode(uint32(0644))},
			"hostname":      {Kind: domain.FileEmuResource, Mode: os.FileMode(uint32(0644))},
			"kptr_restrict": {Kind: domain.FileEmuResource, Mode: os.FileMode(uint32(0644))},
			"ngroups_max":   {Kind: domain.FileEmuResource, Mode: os.FileMode(uint32(0444))},
			"cap_last_cap":  {Kind: domain.FileEmuResource, Mode: os.FileMode(uint32(0444))},
			"panic":         {Kind: domain.FileEmuResource, Mode: os.FileMode(uint32(0644))},
			"panic_on_oops": {Kind: domain.FileEmuResource, Mode: os.FileMode(uint32(0644))},
			"printk":        {Kind: domain.FileEmuResource, Mode: os.FileMode(uint32(0644))},
			"sysrq":         {Kind: domain.FileEmuResource, Mode: os.FileMode(uint32(0644))},
			"pid_max":       {Kind: domain.FileEmuResource, Mode: os.FileMode(uint32(0644))},
		},
		Type:      domain.NODE_SUBSTITUTION,
		Enabled:   true,
		Cacheable: true,
	},
}

func (h *ProcSysKernel) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method for Req ID=%#x on %v handler",
		req.ID, h.Name)

	var lookupNode = filepath.Base(n.Path())

	// Return an artificial fileInfo if looked-up element matches any of the
	// emulated nodes.
	if v, ok := h.EmuResourceMap[lookupNode]; ok {
		info := &domain.FileInfo{
			Fname:    lookupNode,
			Fmode:    v.Mode,
			FmodTime: time.Now(),
		}

		return info, nil
	}

	// If looked-up element hasn't been found by now, let's look into the actual
	// sys container rootfs.
	procSysCommonHandler, ok := h.Service.FindHandler("/proc/sys/")
	if !ok {
		return nil, fmt.Errorf("No /proc/sys/ handler found")
	}

	return procSysCommonHandler.Lookup(n, req)
}

func (h *ProcSysKernel) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	logrus.Debugf("Executing Open() method for Req ID=%#x on %v handler",
		req.ID, h.Name)

	name := n.Name()
	cntr := req.Container

	// Ensure operation is generated from within a registered sys container.
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return errors.New("Container not found")
	}

	flags := n.OpenFlags()

	switch name {
	case "cap_last_cap":
		if flags != syscall.O_RDONLY {
			return fuse.IOerror{Code: syscall.EACCES}
		}
		return nil

	case "pid_max":
		return nil

	case "ngroups_max":
		if flags != syscall.O_RDONLY {
			return fuse.IOerror{Code: syscall.EACCES}
		}
		return nil

	case "domainname":
		return nil

	case "hostname":
		return nil

	case "kptr_restrict":
		return nil

	case "panic":
		return nil

	case "panic_on_oops":
		return nil

	case "sysrq":
		return nil

	case "printk":
		return nil
	}

	procSysCommonHandler, ok := h.Service.FindHandler("/proc/sys/")
	if !ok {
		return fmt.Errorf("No /proc/sys/ handler found")
	}

	return procSysCommonHandler.Open(n, req)
}

func (h *ProcSysKernel) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Read() method for Req ID=%#x on %v handler",
		req.ID, h.Name)

	// We are dealing with a single boolean element being read, so we can save
	// some cycles by returning right away if offset is any higher than zero.
	if req.Offset > 0 {
		return 0, io.EOF
	}

	name := n.Name()
	cntr := req.Container

	// Ensure operation is generated from within a registered sys container.
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return 0, errors.New("Container not found")
	}

	switch name {
	case "cap_last_cap":
		return readFileInt(h, n, req)

	case "pid_max":
		return readFileInt(h, n, req)

	case "ngroups_max":
		return readFileInt(h, n, req)

	case "domainname":
		return readFileString(h, n, req)

	case "hostname":
		return readFileString(h, n, req)

	case "kptr_restrict":
		return readFileInt(h, n, req)

	case "panic":
		return readFileInt(h, n, req)

	case "panic_on_oops":
		return readFileInt(h, n, req)

	case "sysrq":
		return readFileInt(h, n, req)

	case "printk":
		return readFileString(h, n, req)
	}

	// Refer to generic handler if no node match is found above.
	procSysCommonHandler, ok := h.Service.FindHandler("/proc/sys/")
	if !ok {
		return 0, fmt.Errorf("No /proc/sys/ handler found")
	}

	return procSysCommonHandler.Read(n, req)
}

func (h *ProcSysKernel) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Write() method for Req ID=%#x on %v handler",
		req.ID, h.Name)

	name := n.Name()
	cntr := req.Container

	// Ensure operation is generated from within a registered sys container.
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return 0, errors.New("Container not found")
	}

	switch name {
	case "cap_last_cap":
		return 0, nil

	case "ngroups_max":
		return 0, nil

	case "pid_max":
		return writeFileMaxInt(h, n, req, false)

	case "panic":
		return writeFileString(h, n, req, false)

	case "printk":
		return writeFileString(h, n, req, false)

	case "panic_on_oops":
		return writeFileInt(h, n, req, minPanicOopsVal, maxPanicOopsVal, false)

	case "kptr_restrict":
		return writeFileInt(h, n, req, minRestrictVal, maxRestrictVal, false)

	case "sysrq":
		return writeFileInt(h, n, req, minSysrqVal, maxSysrqVal, false)

	case "domainname":
		return writeFileString(h, n, req, false)

	case "hostname":
		return writeFileString(h, n, req, false)
	}

	// Refer to generic handler if no node match is found above.
	procSysCommonHandler, ok := h.Service.FindHandler("/proc/sys/")
	if !ok {
		return 0, fmt.Errorf("No /proc/sys/ handler found")
	}

	return procSysCommonHandler.Write(n, req)
}

func (h *ProcSysKernel) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	logrus.Debugf("Executing ReadDirAll() method for Req ID=%#x on %v handler",
		req.ID, h.Name)

	// Ensure operation is generated from within a registered sys container.
	if req.Container == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return nil, errors.New("Container not found")
	}

	var fileEntries []os.FileInfo

	// Also collect procfs entries as seen within container's namespaces.
	procSysCommonHandler, ok := h.Service.FindHandler("/proc/sys/")
	if !ok {
		return nil, fmt.Errorf("No /proc/sys/ handler found")
	}
	commonNeigh, err := procSysCommonHandler.ReadDirAll(n, req)
	if err == nil {
		for _, entry := range commonNeigh {
			fileEntries = append(fileEntries, entry)
		}
	}

	return fileEntries, nil
}

func (h *ProcSysKernel) GetName() string {
	return h.Name
}

func (h *ProcSysKernel) GetPath() string {
	return h.Path
}

func (h *ProcSysKernel) GetEnabled() bool {
	return h.Enabled
}

func (h *ProcSysKernel) GetType() domain.HandlerType {
	return h.Type
}

func (h *ProcSysKernel) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *ProcSysKernel) GetResourceMap() map[string]domain.EmuResource {
	return h.EmuResourceMap
}

func (h *ProcSysKernel) GetResourceMutex(s string) *sync.Mutex {
	resource, ok := h.EmuResourceMap[s]
	if !ok {
		return nil
	}

	return &resource.Mutex
}

func (h *ProcSysKernel) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *ProcSysKernel) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
