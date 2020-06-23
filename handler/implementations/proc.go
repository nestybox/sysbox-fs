//
// Copyright: (C) 2019-2020 Nestybox Inc.  All rights reserved.
//

package implementations

import (
	"os"
	"syscall"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/sirupsen/logrus"
)

//
// Due to the fact that sysbox-fs' procfs is sourced at /proc/sys, there's no
// much this handler needs to do. This handler's purpose is to be able to manage
// operations associated to /proc bind-mounts such as cpuinfo, meminfo, etc).
//

//
// /proc Handler
//
type ProcHandler struct {
	Name      string
	Path      string
	Type      domain.HandlerType
	Enabled   bool
	Cacheable bool
	Service   domain.HandlerServiceIface
}

func (h *ProcHandler) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method on %v handler", h.Name)

	return n.Stat()
}

func (h *ProcHandler) Getattr(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (*syscall.Stat_t, error) {

	logrus.Debugf("Executing Getattr() method on %v handler", h.Name)

	return nil, nil
}

func (h *ProcHandler) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	logrus.Debugf("Executing %v Open() method", h.Name)

	return nil
}

func (h *ProcHandler) Close(n domain.IOnodeIface) error {

	logrus.Debugf("Executing Close() method on %v handler", h.Name)

	return nil
}

func (h *ProcHandler) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing %v Read() method", h.Name)

	return 0, nil
}

func (h *ProcHandler) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing %v Write() method", h.Name)

	return 0, nil
}

func (h *ProcHandler) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	return nil, nil
}

func (h *ProcHandler) GetName() string {
	return h.Name
}

func (h *ProcHandler) GetPath() string {
	return h.Path
}

func (h *ProcHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *ProcHandler) GetType() domain.HandlerType {
	return h.Type
}

func (h *ProcHandler) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *ProcHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *ProcHandler) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
