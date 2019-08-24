package implementations

import (
	"errors"
	"os"
	"syscall"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
)

//
// This handler's sole purpose is to prevent users in the host file-system from
// being able to list the file contents present in sysbox-fs mountpoint. With
// the exception of lookup(), all operations in this handler will return nil.
// Notice that only users in the host FS can invoke this handler as sysbox-fs
// is mounted in /proc and /proc/sys within the sysbox containers.
//

//
// / Handler
//
type RootHandler struct {
	Name      string
	Path      string
	Enabled   bool
	Cacheable bool
	Service   domain.HandlerService
}

func (h *RootHandler) Lookup(n domain.IOnode, pid uint32) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method on %v handler", h.Name)

	// Identify the pidNsInode corresponding to this pid.
	pidInode := h.Service.FindPidNsInode(pid)
	if pidInode == 0 {
		return nil, errors.New("Could not identify pidNsInode")
	}

	return n.Stat()
}

func (h *RootHandler) Getattr(n domain.IOnode, pid uint32) (*syscall.Stat_t, error) {

	logrus.Debugf("Executing Getattr() method on %v handler", h.Name)

	return nil, nil
}

func (h *RootHandler) Open(n domain.IOnode, pid uint32) error {

	logrus.Debugf("Executing %v Open() method", h.Name)

	return nil
}

func (h *RootHandler) Close(node domain.IOnode) error {

	logrus.Debugf("Executing Close() method on %v handler", h.Name)

	return nil
}

func (h *RootHandler) Read(n domain.IOnode, pid uint32,
	buf []byte, off int64) (int, error) {

	logrus.Debugf("Executing %v Read() method", h.Name)

	return 0, nil
}

func (h *RootHandler) Write(n domain.IOnode, pid uint32,
	buf []byte) (int, error) {

	logrus.Debugf("Executing %v Write() method", h.Name)

	return 0, nil
}

func (h *RootHandler) ReadDirAll(n domain.IOnode, pid uint32) ([]os.FileInfo, error) {

	logrus.Debugf("Executing %v ReadDirAll() method", h.Name)

	return nil, nil
}

func (h *RootHandler) GetName() string {
	return h.Name
}

func (h *RootHandler) GetPath() string {
	return h.Path
}

func (h *RootHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *RootHandler) GetService() domain.HandlerService {
	return h.Service
}

func (h *RootHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *RootHandler) SetService(hs domain.HandlerService) {
	h.Service = hs
}
