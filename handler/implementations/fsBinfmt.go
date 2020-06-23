//
// Copyright: (C) 2019-2020 Nestybox Inc.  All rights reserved.
//

package implementations

import (
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
	Service   domain.HandlerServiceIface
}

func (h *FsBinfmtHandler) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method on %v handler", h.Name)

	return n.Stat()
}

func (h *FsBinfmtHandler) Getattr(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (*syscall.Stat_t, error) {

	logrus.Debugf("Executing Getattr() method on %v handler", h.Name)

	return nil, nil
}

func (h *FsBinfmtHandler) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	logrus.Debugf("Executing %v Open() method", h.Name)

	return nil
}

func (h *FsBinfmtHandler) Close(node domain.IOnodeIface) error {

	logrus.Debugf("Executing Close() method on %v handler", h.Name)

	return nil
}

func (h *FsBinfmtHandler) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing %v Read() method", h.Name)

	return 0, nil
}

func (h *FsBinfmtHandler) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Write() method on %v handler", h.Name)

	return 0, nil
}

func (h *FsBinfmtHandler) ReadDirAll(
	n domain.IOnodeIface,
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

func (h *FsBinfmtHandler) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *FsBinfmtHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *FsBinfmtHandler) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
