//
// Copyright: (C) 2020 Nestybox Inc.  All rights reserved.
//

package implementations

import (
	"errors"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
)

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
type KernelPrintkHandler struct {
	Name      string
	Path      string
	Type      domain.HandlerType
	Enabled   bool
	Cacheable bool
	Service   domain.HandlerService
}

func (h *KernelPrintkHandler) Lookup(
	n domain.IOnode,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method on %v handler", h.Name)

	return n.Stat()
}

func (h *KernelPrintkHandler) Getattr(
	n domain.IOnode,
	req *domain.HandlerRequest) (*syscall.Stat_t, error) {

	logrus.Debugf("Executing Getattr() method on %v handler", h.Name)

	return nil, nil
}

func (h *KernelPrintkHandler) Open(
	n domain.IOnode,
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

func (h *KernelPrintkHandler) Close(n domain.IOnode) error {

	logrus.Debugf("Executing Close() method on %v handler", h.Name)

	if err := n.Close(); err != nil {
		logrus.Debugf("Error closing file %v", h.Path)
		return fuse.IOerror{Code: syscall.EIO}
	}

	return nil
}

func (h *KernelPrintkHandler) Read(
	n domain.IOnode,
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

		data = curHostVal
		cntr.SetData(path, name, data)
	}

	data += "\n"

	return copyResultBuffer(req.Data, []byte(data))
}

func (h *KernelPrintkHandler) Write(
	n domain.IOnode,
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

	// Store the new value within the container struct.
	cntr.SetData(path, name, newVal)

	return len(req.Data), nil
}

func (h *KernelPrintkHandler) ReadDirAll(
	n domain.IOnode,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	return nil, nil
}

func (h *KernelPrintkHandler) GetName() string {
	return h.Name
}

func (h *KernelPrintkHandler) GetPath() string {
	return h.Path
}

func (h *KernelPrintkHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *KernelPrintkHandler) GetType() domain.HandlerType {
	return h.Type
}

func (h *KernelPrintkHandler) GetService() domain.HandlerService {
	return h.Service
}

func (h *KernelPrintkHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *KernelPrintkHandler) SetService(hs domain.HandlerService) {
	h.Service = hs
}
