
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
// /proc/sys/fs/protected_hardlinks handler
//
// Documentation: A long-standing class of security issues is the hardlink-based
// time-of-check-time-of-use race, most commonly seen in world-writable
// directories like /tmp. The common method of exploitation of this flaw is to
// cross privilege boundaries when following a given hardlink (i.e. a root
// process follows a hardlink created by another user). Additionally, on systems
// without separated partitions, this stops unauthorized users from "pinning"
// vulnerable setuid/setgid files against being upgraded by the administrator,
// or linking to special files.
//
// Only two values are supported:
//
// - "0": hardlink creation behavior is unrestricted.
//
// - "1": hardlinks cannot be created by users if they do not already own the
// source file, or do not have read/write access to it.
//
type FsProtectHardLinksHandler struct {
	Name      string
	Path      string
	Type      domain.HandlerType
	Enabled   bool
	Cacheable bool
	Service   domain.HandlerServiceIface
}

func (h *FsProtectHardLinksHandler) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method on %v handler", h.Name)

	return n.Stat()
}

func (h *FsProtectHardLinksHandler) Getattr(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (*syscall.Stat_t, error) {

	logrus.Debugf("Executing Getattr() method on %v handler", h.Name)

	return nil, nil
}

func (h *FsProtectHardLinksHandler) Open(
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

func (h *FsProtectHardLinksHandler) Close(n domain.IOnodeIface) error {

	logrus.Debugf("Executing Close() method on %v handler", h.Name)

	if err := n.Close(); err != nil {
		logrus.Debugf("Error closing file %v", h.Path)
		return fuse.IOerror{Code: syscall.EIO}
	}

	return nil
}

func (h *FsProtectHardLinksHandler) Read(
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

func (h *FsProtectHardLinksHandler) Write(
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
	if newValInt < 0 || newValInt > 1 {
		return 0, fuse.IOerror{Code: syscall.EINVAL}
	}

	// Store the new value within the container struct.
	cntr.SetData(path, name, newVal)

	return len(req.Data), nil
}

func (h *FsProtectHardLinksHandler) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	return nil, nil
}

func (h *FsProtectHardLinksHandler) GetName() string {
	return h.Name
}

func (h *FsProtectHardLinksHandler) GetPath() string {
	return h.Path
}

func (h *FsProtectHardLinksHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *FsProtectHardLinksHandler) GetType() domain.HandlerType {
	return h.Type
}

func (h *FsProtectHardLinksHandler) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *FsProtectHardLinksHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *FsProtectHardLinksHandler) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
