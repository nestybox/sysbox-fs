package implementations

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysvisor-fs/domain"
	"github.com/nestybox/sysvisor-fs/fuse"
)

//
// /proc/partitions Handler
//
type ProcPartitionsHandler struct {
	Name      string
	Path      string
	Enabled   bool
	Cacheable bool
	Service   domain.HandlerService
}

func (h *ProcPartitionsHandler) Lookup(n domain.IOnode, pid uint32) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method on %v handler", h.Name)

	// Identify the pidNsInode corresponding to this pid.
	pidInode := h.Service.FindPidNsInode(pid)
	if pidInode == 0 {
		return nil, errors.New("Could not identify pidNsInode")
	}

	return n.Stat()
}

func (h *ProcPartitionsHandler) Getattr(n domain.IOnode, pid uint32) (*syscall.Stat_t, error) {

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

func (h *ProcPartitionsHandler) Open(n domain.IOnode, pid uint32) error {

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

func (h *ProcPartitionsHandler) Close(n domain.IOnode) error {

	logrus.Debugf("Executing Close() method on %v handler", h.Name)

	return nil
}

func (h *ProcPartitionsHandler) Read(n domain.IOnode, pid uint32,
	buf []byte, off int64) (int, error) {

	logrus.Debugf("Executing %v Read() method", h.Name)

	// Bypass emulation logic for now by going straight to host fs.
	ios := h.Service.IOService()
	len, err := ios.ReadNode(n, buf)
	if err != nil && err != io.EOF {
		return 0, err
	}

	buf = buf[:len]

	return len, nil
}

func (h *ProcPartitionsHandler) Write(n domain.IOnode, pid uint32,
	buf []byte) (int, error) {

	return 0, nil
}

func (h *ProcPartitionsHandler) ReadDirAll(n domain.IOnode,
	pid uint32) ([]os.FileInfo, error) {

	return nil, nil
}

func (h *ProcPartitionsHandler) GetName() string {
	return h.Name
}

func (h *ProcPartitionsHandler) GetPath() string {
	return h.Path
}

func (h *ProcPartitionsHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *ProcPartitionsHandler) GetService() domain.HandlerService {
	return h.Service
}

func (h *ProcPartitionsHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *ProcPartitionsHandler) SetService(hs domain.HandlerService) {
	h.Service = hs
}
