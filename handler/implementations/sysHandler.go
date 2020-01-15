//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

package implementations

import (
	"errors"
	"os"
	"syscall"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/sirupsen/logrus"
)

//
// This is merely a place-holder for upcoming operations requiring "/sys" node
// virtualizations.
//

//
// /sys Handler
//
type SysHandler struct {
	Name      string
	Path      string
	Type      domain.HandlerType
	Enabled   bool
	Cacheable bool
	Service   domain.HandlerService
}

func (h *SysHandler) Lookup(n domain.IOnode, pid uint32) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method on %v handler", h.Name)

	// Identify the pidNsInode corresponding to this pid.
	pidInode := h.Service.FindPidNsInode(pid)
	if pidInode == 0 {
		return nil, errors.New("Could not identify pidNsInode")
	}

	return n.Stat()
}

func (h *SysHandler) Getattr(n domain.IOnode, pid uint32) (*syscall.Stat_t, error) {

	logrus.Debugf("Executing Getattr() method on %v handler", h.Name)

	return nil, nil
}

func (h *SysHandler) Open(n domain.IOnode, pid uint32) error {

	logrus.Debugf("Executing %v Open() method", h.Name)

	return nil
}

func (h *SysHandler) Close(n domain.IOnode) error {

	logrus.Debugf("Executing Close() method on %v handler", h.Name)

	return nil
}

func (h *SysHandler) Read(n domain.IOnode, pid uint32,
	buf []byte, off int64) (int, error) {

	logrus.Debugf("Executing %v Read() method", h.Name)

	return 0, nil
}

func (h *SysHandler) Write(n domain.IOnode, pid uint32,
	buf []byte) (int, error) {

	logrus.Debugf("Executing %v Write() method", h.Name)

	return 0, nil
}

func (h *SysHandler) ReadDirAll(n domain.IOnode, pid uint32) ([]os.FileInfo, error) {

	return nil, nil
}

func (h *SysHandler) GetName() string {
	return h.Name
}

func (h *SysHandler) GetPath() string {
	return h.Path
}

func (h *SysHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *SysHandler) GetType() domain.HandlerType {
	return h.Type
}

func (h *SysHandler) GetService() domain.HandlerService {
	return h.Service
}

func (h *SysHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *SysHandler) SetService(hs domain.HandlerService) {
	h.Service = hs
}
