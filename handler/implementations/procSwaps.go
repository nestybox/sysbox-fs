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
	"syscall"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
)

//
// /proc/swaps Handler
//
type ProcSwapsHandler struct {
	Name      string
	Path      string
	Type      domain.HandlerType
	Enabled   bool
	Cacheable bool
	Service   domain.HandlerService
}

// /proc/swaps static header
var swapsHeader = "Filename                                Type            Size    Used    Priority"


func (h *ProcSwapsHandler) Lookup(n domain.IOnode, pid uint32) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method on %v handler", h.Name)

	// Identify the pidNsInode corresponding to this pid.
	pidInode := h.Service.FindPidNsInode(pid)
	if pidInode == 0 {
		return nil, errors.New("Could not identify pidNsInode")
	}

	return n.Stat()
}

func (h *ProcSwapsHandler) Getattr(n domain.IOnode, pid uint32) (*syscall.Stat_t, error) {

	logrus.Debugf("Executing Getattr() method on %v handler", h.Name)

	// Identify the pidNsInode corresponding to this pid.
	pidInode := h.Service.FindPidNsInode(pid)
	if pidInode == 0 {
		return nil, errors.New("Could not identify pidNsInode")
	}

	// If pidNsInode matches the one of system's true-root, then return here
	// with UID/GID = 0. This step is required during container initialization
	// phase.
	if pidInode == h.Service.HostPidNsInode() {
		stat := &syscall.Stat_t{
			Uid: 0,
			Gid: 0,
		}

		return stat, nil
	}

	// Let's refer to the common handler for the rest.
	commonHandler, ok := h.Service.FindHandler("commonHandler")
	if !ok {
		return nil, fmt.Errorf("No commonHandler found")
	}

	return commonHandler.Getattr(n, pid)
}

func (h *ProcSwapsHandler) Open(n domain.IOnode, pid uint32) error {

	logrus.Debugf("Executing %v Open() method", h.Name)

	flags := n.OpenFlags()
	if flags != syscall.O_RDONLY {
		return fuse.IOerror{Code: syscall.EACCES}
	}

	if err := n.Open(); err != nil {
		logrus.Debug("Error opening file ", h.Path)
		return fuse.IOerror{Code: syscall.EIO}
	}

	return nil
}

func (h *ProcSwapsHandler) Close(n domain.IOnode) error {

	logrus.Debugf("Executing Close() method on %v handler", h.Name)

	return nil
}

func (h *ProcSwapsHandler) Read(n domain.IOnode, pid uint32,
	buf []byte, off int64) (int, error) {

	logrus.Debugf("Executing %v Read() method", h.Name)

	if off > 0 {
		return 0, io.EOF
	}

	// Identify the pidNsInode corresponding to this pid.
	ios := h.Service.IOService()
	tmpNode := ios.NewIOnode("", strconv.Itoa(int(pid)), 0)
	pidInode, err := ios.PidNsInode(tmpNode)
	if err != nil {
		return 0, err
	}

	name := n.Name()
	path := n.Path()

	// Find the container-state corresponding to the container hosting this
	// Pid.
	css := h.Service.StateService()
	cntr := css.ContainerLookupByPid(pidInode)
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pidNsInode %v)", pidInode)
		return 0, errors.New("Container not found")
	}

	// If no modification has been ever made to this container's swapping mode,
	// then let's assume that swapping in OFF by default.
	data, ok := cntr.Data(path, name)
	if !ok || data == "swapoff" {
		result := []byte(swapsHeader + "\n")
		return copyResultBuffer(buf, result)
	}

	var result []byte

	// If swapping is enabled ("swapon" value was explicitly set), extract the
	// information directly from the host fs. Note that this action displays
	// stats of the overall system, and not of the container itself, but it's
	// a valid approximation for now given that kernel doesn't expose anything
	// close to this.
	_, err = ios.ReadNode(n, result)
	if err != nil && err != io.EOF {
		return 0, err
	}

	return copyResultBuffer(buf, result)
}

func (h *ProcSwapsHandler) Write(n domain.IOnode, pid uint32,
	buf []byte) (int, error) {

	return 0, nil
}

func (h *ProcSwapsHandler) ReadDirAll(n domain.IOnode,
	pid uint32) ([]os.FileInfo, error) {

	return nil, nil
}

func (h *ProcSwapsHandler) GetName() string {
	return h.Name
}

func (h *ProcSwapsHandler) GetPath() string {
	return h.Path
}

func (h *ProcSwapsHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *ProcSwapsHandler) GetType() domain.HandlerType {
	return h.Type
}

func (h *ProcSwapsHandler) GetService() domain.HandlerService {
	return h.Service
}

func (h *ProcSwapsHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *ProcSwapsHandler) SetService(hs domain.HandlerService) {
	h.Service = hs
}
