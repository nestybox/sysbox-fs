
package implementations

import (
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
type TestingHandler struct {
	Name      string
	Path      string
	Type      domain.HandlerType
	Enabled   bool
	Cacheable bool
	Service   domain.HandlerServiceIface
}

func (h *TestingHandler) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method on %v handler", h.Name)

	return n.Stat()
}

func (h *TestingHandler) Getattr(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (*syscall.Stat_t, error) {

	logrus.Debugf("Executing Getattr() method on %v handler", h.Name)

	return nil, nil
}

func (h *TestingHandler) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	logrus.Debugf("Executing %v Open() method", h.Name)

	return nil
}

func (h *TestingHandler) Close(node domain.IOnodeIface) error {

	logrus.Debugf("Executing Close() method on %v handler", h.Name)

	return nil
}

func (h *TestingHandler) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing %v Read() method", h.Name)

	if req.Offset > 0 {
		return 0, io.EOF
	}

	return 0, nil
}

func (h *TestingHandler) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	return 0, nil
}

func (h *TestingHandler) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	logrus.Debugf("Executing ReadDirAll() method on %v handler", h.Name)

	commonHandler, ok := h.Service.FindHandler("commonHandler")
	if !ok {
		return nil, fmt.Errorf("No commonHandler found")
	}

	return commonHandler.ReadDirAll(n, req)
}

func (h *TestingHandler) GetName() string {
	return h.Name
}

func (h *TestingHandler) GetPath() string {
	return h.Path
}

func (h *TestingHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *TestingHandler) GetType() domain.HandlerType {
	return h.Type
}

func (h *TestingHandler) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *TestingHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *TestingHandler) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
