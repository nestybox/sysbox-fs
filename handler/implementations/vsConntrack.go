
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
// /proc/sys/net/ipv4/vs/conntrack handler
//
// Note: this resource is already namespaced by the Linux kernel's net-ns. However the
// resource is hidden inside a non-init user-namespace. Thus, this handler's only purpose
// is to expose the resource inside a sys container. The same applies to all other resources
// under "/proc/sys/net/ipv4/vs/", though this handler only deals with "conntrack".
//
type VsConntrackHandler struct {
	Name      string
	Path      string
	Type      domain.HandlerType
	Enabled   bool
	Cacheable bool
	Service   domain.HandlerServiceIface
}

func (h *VsConntrackHandler) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method on %v handler", h.Name)

	return n.Stat()
}

func (h *VsConntrackHandler) Getattr(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (*syscall.Stat_t, error) {

	logrus.Debugf("Executing Getattr() method on %v handler", h.Name)

	return nil, nil
}

func (h *VsConntrackHandler) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	logrus.Debugf("Executing %v Open() method\n", h.Name)

	flags := n.OpenFlags()
	if flags != syscall.O_RDONLY && flags != syscall.O_WRONLY {
		return fuse.IOerror{Code: syscall.EACCES}
	}

	// During 'writeOnly' accesses, we must grant read-write rights temporarily
	// to allow push() to carry out the expected 'write' operation, as well as a
	// 'read' one too.
	if flags == syscall.O_WRONLY {
		n.SetOpenFlags(syscall.O_RDWR)
	}

	if err := n.Open(); err != nil {
		logrus.Debugf("Error opening file %v", h.Path)
		return fuse.IOerror{Code: syscall.EIO}
	}

	return nil
}

func (h *VsConntrackHandler) Close(n domain.IOnodeIface) error {

	logrus.Debugf("Executing Close() method on %v handler", h.Name)

	if err := n.Close(); err != nil {
		logrus.Debugf("Error closing file %v", h.Path)
		return fuse.IOerror{Code: syscall.EIO}
	}

	return nil
}

func (h *VsConntrackHandler) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing %v Read() method", h.Name)

	// We are dealing with a single boolean element being read, so we can save
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

	var err error

	// Check if this resource has been initialized for this container. Otherwise,
	// fetch the information from the host FS and store it accordingly within
	// the container struct.
	data, ok := cntr.Data(path, name)
	if !ok {
		data, err = h.fetchFile(n, cntr)
		if err != nil && err != io.EOF {
			return 0, err
		}

		cntr.SetData(path, name, data)
	}

	data += "\n"

	return copyResultBuffer(req.Data, []byte(data))
}

func (h *VsConntrackHandler) Write(
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
		logrus.Errorf("Unexpected error: %v", err)
		return 0, err
	}

	if err := h.pushFile(n, cntr, newValInt); err != nil {
		return 0, err
	}
	cntr.SetData(path, name, newVal)
	return len(req.Data), nil
}

func (h *VsConntrackHandler) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	return nil, nil
}

func (h *VsConntrackHandler) fetchFile(
	n domain.IOnodeIface,
	c domain.ContainerIface) (string, error) {

	// Read from kernel to extract the existing conntrack value.
	curHostVal, err := n.ReadLine()
	if err != nil && err != io.EOF {
		logrus.Errorf("Could not read from file %v", h.Path)
		return "", err
	}

	// High-level verification to ensure that format is the expected one.
	_, err = strconv.Atoi(curHostVal)
	if err != nil {
		logrus.Errorf("Unexpected content read from file %v, error %v", h.Path, err)
		return "", err
	}

	return curHostVal, nil
}

func (h *VsConntrackHandler) pushFile(
	n domain.IOnodeIface,
	c domain.ContainerIface, newValInt int) error {

	// Push down to kernel the new value.
	msg := []byte(strconv.Itoa(newValInt))
	err := n.WriteFile(msg)
	if err != nil {
		logrus.Errorf("Could not write to file: %v", err)
		return err
	}

	return nil
}

func (h *VsConntrackHandler) GetName() string {
	return h.Name
}

func (h *VsConntrackHandler) GetPath() string {
	return h.Path
}

func (h *VsConntrackHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *VsConntrackHandler) GetType() domain.HandlerType {
	return h.Type
}

func (h *VsConntrackHandler) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *VsConntrackHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *VsConntrackHandler) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
