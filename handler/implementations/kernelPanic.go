//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
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
type KernelPanicHandler struct {
	Name      string
	Path      string
	Type      domain.HandlerType
	Enabled   bool
	Cacheable bool
	Service   domain.HandlerService
}

func (h *KernelPanicHandler) Lookup(n domain.IOnode, pid uint32) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method on %v handler", h.Name)

	// Identify the pidNsInode corresponding to this pid.
	pidInode := h.Service.FindPidNsInode(pid)
	if pidInode == 0 {
		return nil, errors.New("Could not identify pidNsInode")
	}

	return n.Stat()
}

func (h *KernelPanicHandler) Getattr(n domain.IOnode, pid uint32) (*syscall.Stat_t, error) {

	logrus.Debugf("Executing Getattr() method on %v handler", h.Name)

	commonHandler, ok := h.Service.FindHandler("commonHandler")
	if !ok {
		return nil, fmt.Errorf("No commonHandler found")
	}

	return commonHandler.Getattr(n, pid)
}

func (h *KernelPanicHandler) Open(n domain.IOnode, pid uint32) error {

	logrus.Debugf("Executing %v Open() method\n", h.Name)

	flags := n.OpenFlags()
	if flags != syscall.O_RDONLY && flags != syscall.O_WRONLY {
		return fuse.IOerror{Code: syscall.EACCES}
	}

	if err := n.Open(); err != nil {
		logrus.Debug("Error opening file ", h.Path)
		return fuse.IOerror{Code: syscall.EIO}
	}

	return nil
}

func (h *KernelPanicHandler) Close(n domain.IOnode) error {

	logrus.Debugf("Executing Close() method on %v handler", h.Name)

	return nil
}

func (h *KernelPanicHandler) Read(n domain.IOnode, pid uint32,
	buf []byte, off int64) (int, error) {

	logrus.Debugf("Executing %v Read() method", h.Name)

	// We are dealing with a single integer element being read, so we can save
	// some cycles by returning right away if offset is any higher than zero.
	if off > 0 {
		return 0, io.EOF
	}

	name := n.Name()
	path := n.Path()

	// Identify the pidNsInode corresponding to this pid.
	ios := h.Service.IOService()
	tmpNode := ios.NewIOnode("", strconv.Itoa(int(pid)), 0)
	pidInode, err := ios.PidNsInode(tmpNode)
	if err != nil {
		return 0, err
	}

	// Find the container-state corresponding to the container hosting this
	// Pid.
	css := h.Service.StateService()
	cntr := css.ContainerLookupByPid(pidInode)
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pidNsInode %v)", pidInode)
		return 0, errors.New("Container not found")
	}

	// Check if this resource has been initialized for this container. Otherwise,
	// fetch the information from the host FS and store it accordingly within
	// the container struct.
	data, ok := cntr.Data(path, name)
	if !ok {
		// Read from host FS to extract the existing 'panic' interval value.
		curHostVal, err := n.ReadLine()
		if err != nil && err != io.EOF {
			logrus.Error("Could not read from file ", h.Path)
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
	copy(buf, data)
	length := len(data)
	buf = buf[:length]

	return length, nil
}

func (h *KernelPanicHandler) Write(n domain.IOnode, pid uint32,
	buf []byte) (int, error) {

	logrus.Debugf("Executing %v Write() method", h.Name)

	name := n.Name()
	path := n.Path()

	newVal := strings.TrimSpace(string(buf))
	_, err := strconv.Atoi(newVal)
	if err != nil {
		logrus.Error("Unsupported kernel_panic value: ", newVal)
		return 0, fuse.IOerror{Code: syscall.EINVAL}
	}

	// Identify the pidNsInode corresponding to this pid.
	ios := h.Service.IOService()
	tmpNode := ios.NewIOnode("", strconv.Itoa(int(pid)), 0)
	pidInode, err := ios.PidNsInode(tmpNode)
	if err != nil {
		return 0, err
	}

	// Find the container-state corresponding to the container hosting this
	// Pid.
	css := h.Service.StateService()
	cntr := css.ContainerLookupByPid(pidInode)
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pidNsInode %v)", pidInode)
		return 0, errors.New("Container not found")
	}

	// Store the new value within the container struct.
	cntr.SetData(path, name, newVal)

	return len(buf), nil
}

func (h *KernelPanicHandler) ReadDirAll(n domain.IOnode, pid uint32) ([]os.FileInfo, error) {
	return nil, nil
}

func (h *KernelPanicHandler) GetName() string {
	return h.Name
}

func (h *KernelPanicHandler) GetPath() string {
	return h.Path
}

func (h *KernelPanicHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *KernelPanicHandler) GetType() domain.HandlerType {
	return h.Type
}

func (h *KernelPanicHandler) GetService() domain.HandlerService {
	return h.Service
}

func (h *KernelPanicHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *KernelPanicHandler) SetService(hs domain.HandlerService) {
	h.Service = hs
}
