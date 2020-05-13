//
// Copyright: (C) 2020 Nestybox Inc.  All rights reserved.
//

package implementations

import (
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
)

//
// /proc/sys/kernel/yama/ptrace_scope handler
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

type KernelYamaPtraceScopeHandler struct {
	Name      string
	Path      string
	Type      domain.HandlerType
	Enabled   bool
	Cacheable bool
	Service   domain.HandlerServiceIface
}

func (h *KernelYamaPtraceScopeHandler) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method on %v handler", h.Name)

	return n.Stat()
}

func (h *KernelYamaPtraceScopeHandler) Getattr(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (*syscall.Stat_t, error) {

	logrus.Debugf("Executing Getattr() method on %v handler", h.Name)

	return nil, nil
}

func (h *KernelYamaPtraceScopeHandler) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	logrus.Debugf("Executing %v Open() method\n", h.Name)

	flags := n.OpenFlags()
	if flags != syscall.O_RDONLY && flags != syscall.O_WRONLY {
		return fuse.IOerror{Code: syscall.EACCES}
	}

	if err := n.Open(); err != nil {
		logrus.Debugf("Error opening file %v", h.Path)
		return fuse.IOerror{Code: syscall.EIO}
	}

	return nil
}

func (h *KernelYamaPtraceScopeHandler) Close(n domain.IOnodeIface) error {

	logrus.Debugf("Executing Close() method on %v handler", h.Name)

	if err := n.Close(); err != nil {
		logrus.Debugf("Error closing file %v", h.Path)
		return fuse.IOerror{Code: syscall.EIO}
	}

	return nil
}

func (h *KernelYamaPtraceScopeHandler) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing %v Read() method", h.Name)

	// We are dealing with a single integer element being read, so we can save
	// some cycles by returning right away if offset is any higher than zero.
	if req.Offset > 0 {
		return 0, io.EOF
	}

	name := n.Name()
	path := n.Path()
	cntr := req.Container

	// Ensure operation is generated from within a registered sys container.
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return 0, errors.New("Container not found")
	}

	// Check if this resource has been initialized for this container. Otherwise,
	// fetch the information from the host FS and store it accordingly within
	// the container struct.
	data, ok := cntr.Data(path, name)
	if !ok {
		// Read from host FS to extract the existing value.
		curHostVal, err := n.ReadLine()
		if err != nil && err != io.EOF {
			logrus.Errorf("Could not read from file %v", h.Path)
			return 0, fuse.IOerror{Code: syscall.EIO}
		}

		// High-level verification to ensure that format is the expected one.
		_, err = strconv.Atoi(curHostVal)
		if err != nil {
			logrus.Errorf("Unsupported content read from file %v, error %v", h.Path, err)
			return 0, fuse.IOerror{Code: syscall.EINVAL}
		}

		data = curHostVal
		cntr.SetData(path, name, data)
	}

	data += "\n"

	return copyResultBuffer(req.Data, []byte(data))
}

func (h *KernelYamaPtraceScopeHandler) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing %v Write() method", h.Name)

	name := n.Name()
	path := n.Path()
	cntr := req.Container

	// Ensure operation is generated from within a registered sys container.
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return 0, errors.New("Container not found")
	}

	newVal := strings.TrimSpace(string(req.Data))
	newValInt, err := strconv.Atoi(newVal)
	if err != nil {
		return 0, fuse.IOerror{Code: syscall.EINVAL}
	}

	// Ensure that only proper values are allowed as per this resource's
	// supported values.
	if newValInt < minScopeVal || newValInt > maxScopeVal {
		return 0, fuse.IOerror{Code: syscall.EINVAL}
	}

	// Store the new value within the container struct.
	cntr.SetData(path, name, newVal)

	return len(req.Data), nil
}

func (h *KernelYamaPtraceScopeHandler) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	return nil, nil
}

func (h *KernelYamaPtraceScopeHandler) GetName() string {
	return h.Name
}

func (h *KernelYamaPtraceScopeHandler) GetPath() string {
	return h.Path
}

func (h *KernelYamaPtraceScopeHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *KernelYamaPtraceScopeHandler) GetType() domain.HandlerType {
	return h.Type
}

func (h *KernelYamaPtraceScopeHandler) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *KernelYamaPtraceScopeHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *KernelYamaPtraceScopeHandler) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
