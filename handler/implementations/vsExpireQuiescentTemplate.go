//
// Copyright: (C) 2020 Nestybox Inc.  All rights reserved.
//

package implementations

import (
	"errors"
	"fmt"
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
// /proc/sys/net/ipv4/vs/expire_quiescent_template handler
//
// Note: this resource is already namespaced by the Linux kernel's net-ns. However the
// resource is hidden inside a non-init user-namespace. Thus, this handler's only purpose
// is to expose the resource inside a sys container. The same applies to all other resources
// under "/proc/sys/net/ipv4/vs/", though this handler only deals with "expire_quiescent_template".
//
type VsExpireQuiescentTemplateHandler struct {
	Name      string
	Path      string
	Type      domain.HandlerType
	Enabled   bool
	Cacheable bool
	Service   domain.HandlerService
}

func (h *VsExpireQuiescentTemplateHandler) Lookup(n domain.IOnode, pid uint32) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method on %v handler", h.Name)

	// Identify the pidNsInode corresponding to this pid.
	pidInode := h.Service.FindPidNsInode(pid)
	if pidInode == 0 {
		return nil, errors.New("Could not identify pidNsInode")
	}

	return n.Stat()
}

func (h *VsExpireQuiescentTemplateHandler) Getattr(n domain.IOnode, pid uint32) (*syscall.Stat_t, error) {

	logrus.Debugf("Executing Getattr() method on %v handler", h.Name)

	commonHandler, ok := h.Service.FindHandler("commonHandler")
	if !ok {
		return nil, fmt.Errorf("No commonHandler found")
	}

	return commonHandler.Getattr(n, pid)
}

func (h *VsExpireQuiescentTemplateHandler) Open(n domain.IOnode, pid uint32) error {

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
		logrus.Debug("Error opening file ", h.Path)
		return fuse.IOerror{Code: syscall.EIO}
	}

	return nil
}

func (h *VsExpireQuiescentTemplateHandler) Close(n domain.IOnode) error {

	logrus.Debugf("Executing Close() method on %v handler", h.Name)

	if err := n.Close(); err != nil {
		logrus.Debug("Error closing file ", h.Path)
		return fuse.IOerror{Code: syscall.EIO}
	}

	return nil
}

func (h *VsExpireQuiescentTemplateHandler) Read(n domain.IOnode, pid uint32,
	buf []byte, off int64) (int, error) {

	logrus.Debugf("Executing %v Read() method", h.Name)

	// We are dealing with a single boolean element being read, so we can save
	// some cycles by returning right away if offset is any higher than zero.
	if off > 0 {
		return 0, io.EOF
	}

	name := n.Name()
	path := n.Path()

	// Identify the container holding the process represented by this pid. This
	// action can only succeed if the associated container has been previously
	// registered with sysbox-fs.
	css := h.Service.StateService()
	cntr := css.ContainerLookupByPid(pid)
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)", pid)
		return 0, errors.New("Container not found")
	}

	var err error

	// Check if this resource has been initialized for this container. Otherwise,
	// fetch the information from the host FS and store it accordingly within
	// the container struct.
	data, ok := cntr.Data(path, name)
	if !ok {
		data, err = h.FetchFile(n, cntr)
		if err != nil && err != io.EOF {
			return 0, err
		}

		cntr.SetData(path, name, data)
	}

	data += "\n"

	return copyResultBuffer(buf, []byte(data))
}

func (h *VsExpireQuiescentTemplateHandler) Write(n domain.IOnode, pid uint32,
	buf []byte) (int, error) {

	logrus.Debugf("Executing %v Write() method", h.Name)

	name := n.Name()
	path := n.Path()

	newVal := strings.TrimSpace(string(buf))
	newValInt, err := strconv.Atoi(newVal)
	if err != nil {
		logrus.Error("Unexpected error: ", err)
		return 0, err
	}

	// Identify the container holding the process represented by this pid. This
	// action can only succeed if the associated container has been previously
	// registered with sysbox-fs.
	css := h.Service.StateService()
	cntr := css.ContainerLookupByPid(pid)
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)", pid)
		return 0, errors.New("Container not found")
	}

	if err := h.PushFile(n, cntr, newValInt); err != nil {
		return 0, err
	}
	cntr.SetData(path, name, newVal)
	return len(buf), nil
}

func (h *VsExpireQuiescentTemplateHandler) ReadDirAll(n domain.IOnode, pid uint32) ([]os.FileInfo, error) {
	return nil, nil
}

func (h *VsExpireQuiescentTemplateHandler) FetchFile(n domain.IOnode, c domain.ContainerIface) (string, error) {

	// Read from kernel to extract the existing expire_quiescent_template value.
	curHostVal, err := n.ReadLine()
	if err != nil && err != io.EOF {
		logrus.Error("Could not read from file ", h.Path)
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

func (h *VsExpireQuiescentTemplateHandler) PushFile(n domain.IOnode, c domain.ContainerIface, newValInt int) error {

	// Rewinding file offset back to its start point.
	_, err := n.SeekReset()
	if err != nil {
		logrus.Error("Could not reset file offset: ", err)
		return err
	}

	// Push down to kernel the new value.
	msg := []byte(strconv.Itoa(newValInt))
	_, err = n.Write(msg)
	if err != nil {
		logrus.Error("Could not write to file: ", err)
		return err
	}

	return nil
}

func (h *VsExpireQuiescentTemplateHandler) GetName() string {
	return h.Name
}

func (h *VsExpireQuiescentTemplateHandler) GetPath() string {
	return h.Path
}

func (h *VsExpireQuiescentTemplateHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *VsExpireQuiescentTemplateHandler) GetType() domain.HandlerType {
	return h.Type
}

func (h *VsExpireQuiescentTemplateHandler) GetService() domain.HandlerService {
	return h.Service
}

func (h *VsExpireQuiescentTemplateHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *VsExpireQuiescentTemplateHandler) SetService(hs domain.HandlerService) {
	h.Service = hs
}
