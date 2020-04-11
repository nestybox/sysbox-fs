//
// Copyright: (C) 2019-2020 Nestybox Inc.  All rights reserved.
//

package implementations

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"syscall"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
)

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

type KernelNgroupsMaxHandler struct {
	Name      string
	Path      string
	Type      domain.HandlerType
	Enabled   bool
	Cacheable bool
	Service   domain.HandlerService
}

func (h *KernelNgroupsMaxHandler) Lookup(
	n domain.IOnode,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method on %v handler", h.Name)

	return n.Stat()
}

func (h *KernelNgroupsMaxHandler) Getattr(
	n domain.IOnode,
	req *domain.HandlerRequest) (*syscall.Stat_t, error) {

	logrus.Debugf("Executing Getattr() method on %v handler", h.Name)

	commonHandler, ok := h.Service.FindHandler("commonHandler")
	if !ok {
		return nil, fmt.Errorf("No commonHandler found")
	}

	return commonHandler.Getattr(n, req)
}

func (h *KernelNgroupsMaxHandler) Open(
	n domain.IOnode,
	req *domain.HandlerRequest) error {

	logrus.Debugf("Executing %v Open() method\n", h.Name)

	flags := n.OpenFlags()
	if flags != syscall.O_RDONLY {
		return fuse.IOerror{Code: syscall.EACCES}
	}

	if err := n.Open(); err != nil {
		logrus.Debugf("Error opening file %v", h.Path)
		return fuse.IOerror{Code: syscall.EIO}
	}

	return nil
}

func (h *KernelNgroupsMaxHandler) Close(n domain.IOnode) error {

	logrus.Debugf("Executing Close() method on %v handler", h.Name)

	if err := n.Close(); err != nil {
		logrus.Debugf("Error closing file %v", h.Path)
		return fuse.IOerror{Code: syscall.EIO}
	}

	return nil
}

func (h *KernelNgroupsMaxHandler) Read(
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
		// Read from host FS to extract the existing 'ngroups_max' value.
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

func (h *KernelNgroupsMaxHandler) Write(
	n domain.IOnode,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing %v Write() method", h.Name)

	return 0, nil
}

func (h *KernelNgroupsMaxHandler) ReadDirAll(
	n domain.IOnode,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	return nil, nil
}

func (h *KernelNgroupsMaxHandler) GetName() string {
	return h.Name
}

func (h *KernelNgroupsMaxHandler) GetPath() string {
	return h.Path
}

func (h *KernelNgroupsMaxHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *KernelNgroupsMaxHandler) GetType() domain.HandlerType {
	return h.Type
}

func (h *KernelNgroupsMaxHandler) GetService() domain.HandlerService {
	return h.Service
}

func (h *KernelNgroupsMaxHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *KernelNgroupsMaxHandler) SetService(hs domain.HandlerService) {
	h.Service = hs
}
