//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

package implementations

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
)

//
// /proc/sys Handler
//
type FsBinfmtHandler struct {
	Name      string
	Path      string
	Type      domain.HandlerType
	Enabled   bool
	Cacheable bool
	Service   domain.HandlerService
}

func (h *FsBinfmtHandler) Lookup(
	n domain.IOnode,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method on %v handler", h.Name)

	// Identify the userNsInode corresponding to this pid.
	usernsInode := h.Service.FindUserNsInode(req.Pid)
	if usernsInode == 0 {
		return nil, errors.New("Could not identify userNsInode")
	}

	return n.Stat()
}

func (h *FsBinfmtHandler) Getattr(
	n domain.IOnode,
	req *domain.HandlerRequest) (*syscall.Stat_t, error) {

	logrus.Debugf("Executing Getattr() method on %v handler", h.Name)

	// Identify the userNsInode corresponding to this pid.
	usernsInode := h.Service.FindUserNsInode(req.Pid)
	if usernsInode == 0 {
		return nil, errors.New("Could not identify userNsInode")
	}

	// If userNsInode matches the one of system's true-root, then return here
	// with UID/GID = 0. This step is required during container initialization
	// phase.
	if usernsInode == h.Service.HostUserNsInode() {
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

	return commonHandler.Getattr(n, req)
}

func (h *FsBinfmtHandler) Open(
	n domain.IOnode,
	req *domain.HandlerRequest) error {

	logrus.Debugf("Executing %v Open() method", h.Name)

	return nil
}

func (h *FsBinfmtHandler) Close(node domain.IOnode) error {

	logrus.Debugf("Executing Close() method on %v handler", h.Name)

	return nil
}

func (h *FsBinfmtHandler) Read(
	n domain.IOnode,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing %v Read() method", h.Name)

	if req.Offset > 0 {
		return 0, io.EOF
	}

	return 0, nil
}

func (h *FsBinfmtHandler) Write(
	n domain.IOnode,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Write() method on %v handler", h.Name)

	return 0, nil
}

func (h *FsBinfmtHandler) ReadDirAll(
	n domain.IOnode,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	logrus.Debugf("Executing ReadDirAll() method on %v handler", h.Name)

	return nil, nil
}

func (h *FsBinfmtHandler) GetName() string {
	return h.Name
}

func (h *FsBinfmtHandler) GetPath() string {
	return h.Path
}

func (h *FsBinfmtHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *FsBinfmtHandler) GetType() domain.HandlerType {
	return h.Type
}

func (h *FsBinfmtHandler) GetService() domain.HandlerService {
	return h.Service
}

func (h *FsBinfmtHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *FsBinfmtHandler) SetService(hs domain.HandlerService) {
	h.Service = hs
}
