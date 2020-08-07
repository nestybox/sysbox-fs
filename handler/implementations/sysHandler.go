
package implementations

import (
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
	Service   domain.HandlerServiceIface
}

func (h *SysHandler) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method on %v handler", h.Name)

	return n.Stat()
}

func (h *SysHandler) Getattr(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (*syscall.Stat_t, error) {

	logrus.Debugf("Executing Getattr() method on %v handler", h.Name)

	return nil, nil
}

func (h *SysHandler) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	logrus.Debugf("Executing %v Open() method", h.Name)

	return nil
}

func (h *SysHandler) Close(n domain.IOnodeIface) error {

	logrus.Debugf("Executing Close() method on %v handler", h.Name)

	return nil
}

func (h *SysHandler) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing %v Read() method", h.Name)

	return 0, nil
}

func (h *SysHandler) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing %v Write() method", h.Name)

	return 0, nil
}

func (h *SysHandler) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

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

func (h *SysHandler) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *SysHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *SysHandler) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
