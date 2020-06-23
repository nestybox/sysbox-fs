//
// Copyright: (C) 2019-2020 Nestybox Inc.  All rights reserved.
//

package implementations

import (
	"io"
	"os"
	"syscall"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
)

//
// /proc/pagetypeinfo Handler
//
type ProcPagetypeinfoHandler struct {
	Name      string
	Path      string
	Type      domain.HandlerType
	Enabled   bool
	Cacheable bool
	Service   domain.HandlerServiceIface
}

func (h *ProcPagetypeinfoHandler) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method on %v handler", h.Name)

	return n.Stat()
}

func (h *ProcPagetypeinfoHandler) Getattr(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (*syscall.Stat_t, error) {

	logrus.Debugf("Executing Getattr() method on %v handler", h.Name)

	return nil, nil
}

func (h *ProcPagetypeinfoHandler) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	logrus.Debugf("Executing %v Open() method", h.Name)

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

func (h *ProcPagetypeinfoHandler) Close(n domain.IOnodeIface) error {

	logrus.Debugf("Executing Close() method on %v handler", h.Name)

	if err := n.Close(); err != nil {
		logrus.Debugf("Error closing file %v", h.Path)
		return fuse.IOerror{Code: syscall.EIO}
	}

	return nil
}

func (h *ProcPagetypeinfoHandler) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing %v Read() method", h.Name)

	// Bypass emulation logic for now by going straight to host fs.
	ios := h.Service.IOService()
	len, err := ios.ReadNode(n, req.Data)
	if err != nil && err != io.EOF {
		return 0, err
	}

	req.Data = req.Data[:len]

	return len, nil
}

func (h *ProcPagetypeinfoHandler) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	return 0, nil
}

func (h *ProcPagetypeinfoHandler) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	return nil, nil
}

func (h *ProcPagetypeinfoHandler) GetName() string {
	return h.Name
}

func (h *ProcPagetypeinfoHandler) GetPath() string {
	return h.Path
}

func (h *ProcPagetypeinfoHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *ProcPagetypeinfoHandler) GetType() domain.HandlerType {
	return h.Type
}

func (h *ProcPagetypeinfoHandler) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *ProcPagetypeinfoHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *ProcPagetypeinfoHandler) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
