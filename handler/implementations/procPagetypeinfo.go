package implementations

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"syscall"

	"github.com/nestybox/sysvisor-fs/domain"
)

//
// /proc/pagetypeinfo Handler
//
type ProcPagetypeinfoHandler struct {
	Name      string
	Path      string
	Enabled   bool
	Cacheable bool
	Service   domain.HandlerService
}

func (h *ProcPagetypeinfoHandler) Lookup(n domain.IOnode, pid uint32) (os.FileInfo, error) {

	log.Printf("Executing Lookup() method on %v handler", h.Name)

	// Identify the pidNsInode corresponding to this pid.
	pidInode := h.Service.FindPidNsInode(pid)
	if pidInode == 0 {
		return nil, errors.New("Could not identify pidNsInode")
	}

	return n.Stat()
}

func (h *ProcPagetypeinfoHandler) Getattr(n domain.IOnode, pid uint32) (*syscall.Stat_t, error) {

	log.Printf("Executing Getattr() method on %v handler", h.Name)

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

func (h *ProcPagetypeinfoHandler) Open(n domain.IOnode) error {

	log.Printf("Executing %v open() method", h.Name)

	flags := n.OpenFlags()
	if flags != syscall.O_RDONLY {
		return syscall.EACCES
	}

	if err := n.Open(); err != nil {
		log.Printf("Error opening file %v\n", h.Path)
		return syscall.EIO
	}

	return nil
}

func (h *ProcPagetypeinfoHandler) Close(n domain.IOnode) error {

	log.Printf("Executing Close() method on %v handler", h.Name)

	return nil
}

func (h *ProcPagetypeinfoHandler) Read(n domain.IOnode, pid uint32,
	buf []byte, off int64) (int, error) {

	log.Printf("Executing %v read() method", h.Name)

	// Bypass emulation logic for now by going straight to host fs.
	ios := h.Service.IOService()
	len, err := ios.ReadNode(n, buf)
	if err != nil && err != io.EOF {
		return 0, err
	}

	buf = buf[:len]

	return len, nil
}

func (h *ProcPagetypeinfoHandler) Write(n domain.IOnode, pid uint32,
	buf []byte) (int, error) {

	return 0, nil
}

func (h *ProcPagetypeinfoHandler) ReadDirAll(n domain.IOnode,
	pid uint32) ([]os.FileInfo, error) {

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

func (h *ProcPagetypeinfoHandler) GetService() domain.HandlerService {
	return h.Service
}

func (h *ProcPagetypeinfoHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *ProcPagetypeinfoHandler) SetService(hs domain.HandlerService) {
	h.Service = hs
}
