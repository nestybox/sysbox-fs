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
type KernelPanicOopsHandler struct {
	Name      string
	Path      string
	Type      domain.HandlerType
	Enabled   bool
	Cacheable bool
	Service   domain.HandlerService
}

func (h *KernelPanicOopsHandler) Lookup(
	n domain.IOnode,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method on %v handler", h.Name)

	return n.Stat()
}

func (h *KernelPanicOopsHandler) Getattr(
	n domain.IOnode,
	req *domain.HandlerRequest) (*syscall.Stat_t, error) {

	logrus.Debugf("Executing Getattr() method on %v handler", h.Name)

	commonHandler, ok := h.Service.FindHandler("commonHandler")
	if !ok {
		return nil, fmt.Errorf("No commonHandler found")
	}

	return commonHandler.Getattr(n, req)
}

func (h *KernelPanicOopsHandler) Open(
	n domain.IOnode,
	req *domain.HandlerRequest) error {

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

func (h *KernelPanicOopsHandler) Close(n domain.IOnode) error {

	logrus.Debugf("Executing Close() method on %v handler", h.Name)

	if err := n.Close(); err != nil {
		logrus.Debug("Error closing file ", h.Path)
		return fuse.IOerror{Code: syscall.EIO}
	}

	return nil
}

func (h *KernelPanicOopsHandler) Read(
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

	prs := h.Service.ProcessService()
	process := prs.ProcessCreate(req.Pid, 0, 0)

	// Identify the container holding the process represented by this pid. This
	// action can only succeed if the associated container has been previously
	// registered in sysbox-fs.
	css := h.Service.StateService()
	cntr := css.ContainerLookupByProcess(process)
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

	return copyResultBuffer(req.Data, []byte(data))
}

func (h *KernelPanicOopsHandler) Write(
	n domain.IOnode,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing %v Write() method", h.Name)

	name := n.Name()
	path := n.Path()

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

	prs := h.Service.ProcessService()
	process := prs.ProcessCreate(req.Pid, 0, 0)

	// Identify the container holding the process represented by this pid. This
	// action can only succeed if the associated container has been previously
	// registered in sysbox-fs.
	css := h.Service.StateService()
	cntr := css.ContainerLookupByProcess(process)
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return 0, errors.New("Container not found")
	}

	// Store the new value within the container struct.
	cntr.SetData(path, name, newVal)

	return len(req.Data), nil
}

func (h *KernelPanicOopsHandler) ReadDirAll(
	n domain.IOnode,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	return nil, nil
}

func (h *KernelPanicOopsHandler) GetName() string {
	return h.Name
}

func (h *KernelPanicOopsHandler) GetPath() string {
	return h.Path
}

func (h *KernelPanicOopsHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *KernelPanicOopsHandler) GetType() domain.HandlerType {
	return h.Type
}

func (h *KernelPanicOopsHandler) GetService() domain.HandlerService {
	return h.Service
}

func (h *KernelPanicOopsHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *KernelPanicOopsHandler) SetService(hs domain.HandlerService) {
	h.Service = hs
}
