//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

package implementations

import (
	"os"
	"syscall"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
)

//
// /proc/sys/fs/binfmt_misc/status Handler
//
type FsBinfmtStatusHandler struct {
	Name      string
	Path      string
	Type      domain.HandlerType
	Enabled   bool
	Cacheable bool
	Service   domain.HandlerService
}

func (h *FsBinfmtStatusHandler) Lookup(
	n domain.IOnode,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method on %v handler", h.Name)

	return nil, fuse.IOerror{Code: syscall.ENOENT}
}

func (h *FsBinfmtStatusHandler) Getattr(
	n domain.IOnode,
	req *domain.HandlerRequest) (*syscall.Stat_t, error) {

	logrus.Debugf("Executing Getattr() method on %v handler", h.Name)

	return nil, nil
}

func (h *FsBinfmtStatusHandler) Open(
	n domain.IOnode,
	req *domain.HandlerRequest) error {

	logrus.Debugf("Executing %v Open() method", h.Name)

	return nil
}

func (h *FsBinfmtStatusHandler) Close(node domain.IOnode) error {

	logrus.Debugf("Executing Close() method on %v handler", h.Name)

	return nil
}

func (h *FsBinfmtStatusHandler) Read(
	n domain.IOnode,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing %v Read() method", h.Name)

	return 0, nil
}

func (h *FsBinfmtStatusHandler) Write(
	n domain.IOnode,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing %v Write() method", h.Name)

	return 0, nil
}

func (h *FsBinfmtStatusHandler) ReadDirAll(
	n domain.IOnode,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	logrus.Debugf("Executing %v ReadDirAll() method", h.Name)

	return nil, nil
}

func (h *FsBinfmtStatusHandler) GetName() string {
	return h.Name
}

func (h *FsBinfmtStatusHandler) GetPath() string {
	return h.Path
}

func (h *FsBinfmtStatusHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *FsBinfmtStatusHandler) GetType() domain.HandlerType {
	return h.Type
}

func (h *FsBinfmtStatusHandler) GetService() domain.HandlerService {
	return h.Service
}

func (h *FsBinfmtStatusHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *FsBinfmtStatusHandler) SetService(hs domain.HandlerService) {
	h.Service = hs
}
