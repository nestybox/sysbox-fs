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
// /proc/sys/net/ipv4/vs/conn_reuse_mode handler
//
// Note: this resource is already namespaced by the Linux kernel's net-ns. However the
// resource is hidden inside a non-init user-namespace. Thus, this handler's only purpose
// is to expose the resource inside a sys container. The same applies to all other resources
// under "/proc/sys/net/ipv4/vs/", though this handler only deals with "conn_reuse_mode".
//
type VsConnReuseModeHandler struct {
	Name      string
	Path      string
	Type      domain.HandlerType
	Enabled   bool
	Cacheable bool
	Service   domain.HandlerService
}

func (h *VsConnReuseModeHandler) Lookup(
	n domain.IOnode,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method on %v handler", h.Name)

	return n.Stat()
}

func (h *VsConnReuseModeHandler) Getattr(
	n domain.IOnode,
	req *domain.HandlerRequest) (*syscall.Stat_t, error) {

	logrus.Debugf("Executing Getattr() method on %v handler", h.Name)

	return nil, nil
}

func (h *VsConnReuseModeHandler) Open(
	n domain.IOnode,
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

func (h *VsConnReuseModeHandler) Close(n domain.IOnode) error {

	logrus.Debugf("Executing Close() method on %v handler", h.Name)

	if err := n.Close(); err != nil {
		logrus.Debugf("Error closing file %v", h.Path)
		return fuse.IOerror{Code: syscall.EIO}
	}

	return nil
}

func (h *VsConnReuseModeHandler) Read(
	n domain.IOnode,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing %v Read() method", h.Name)

	// We are dealing with a single boolean element being read, so we can save
	// some cycles by returning right away if offset is any higher than zero.
	if req.Offset > 0 {
		return 0, io.EOF
	}

	name := n.Name()
	path := n.Path()

	prs := h.Service.ProcessService()
	process := prs.ProcessCreate(req.Pid, 0, 0)

	// Identify the container holding the process represented by this pid. This
	// action can only succeed if the associated container has been previously
	// registered with sysbox-fs.
	css := h.Service.StateService()
	cntr := css.ContainerLookupByProcess(process)
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

func (h *VsConnReuseModeHandler) Write(
	n domain.IOnode,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing %v Write() method", h.Name)

	name := n.Name()
	path := n.Path()

	newVal := strings.TrimSpace(string(req.Data))
	newValInt, err := strconv.Atoi(newVal)
	if err != nil {
		logrus.Errorf("Unexpected error: %v", err)
		return 0, err
	}

	prs := h.Service.ProcessService()
	process := prs.ProcessCreate(req.Pid, 0, 0)

	// Identify the container holding the process represented by this pid. This
	// action can only succeed if the associated container has been previously
	// registered with sysbox-fs.
	css := h.Service.StateService()
	cntr := css.ContainerLookupByProcess(process)
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return 0, errors.New("Container not found")
	}

	if err := h.pushFile(n, cntr, newValInt); err != nil {
		return 0, err
	}
	cntr.SetData(path, name, newVal)
	return len(req.Data), nil
}

func (h *VsConnReuseModeHandler) ReadDirAll(
	n domain.IOnode,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	return nil, nil
}

func (h *VsConnReuseModeHandler) fetchFile(
	n domain.IOnode,
	c domain.ContainerIface) (string, error) {

	// Read from kernel to extract the existing conn_reuse_mode value.
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

func (h *VsConnReuseModeHandler) pushFile(
	n domain.IOnode,
	c domain.ContainerIface,
	newValInt int) error {

	// Rewinding file offset back to its start point.
	_, err := n.SeekReset()
	if err != nil {
		logrus.Errorf("Could not reset file offset: %v", err)
		return err
	}

	// Push down to kernel the new value.
	msg := []byte(strconv.Itoa(newValInt))
	_, err = n.Write(msg)
	if err != nil {
		logrus.Errorf("Could not write to file: %v", err)
		return err
	}

	return nil
}

func (h *VsConnReuseModeHandler) GetName() string {
	return h.Name
}

func (h *VsConnReuseModeHandler) GetPath() string {
	return h.Path
}

func (h *VsConnReuseModeHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *VsConnReuseModeHandler) GetType() domain.HandlerType {
	return h.Type
}

func (h *VsConnReuseModeHandler) GetService() domain.HandlerService {
	return h.Service
}

func (h *VsConnReuseModeHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *VsConnReuseModeHandler) SetService(hs domain.HandlerService) {
	h.Service = hs
}
