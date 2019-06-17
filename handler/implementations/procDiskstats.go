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
// /proc/cgroups Handler
//
type ProcDiskstatsHandler struct {
	Name      string
	Path      string
	Enabled   bool
	Cacheable bool
	Service   domain.HandlerService
}

func (h *ProcDiskstatsHandler) Lookup(n domain.IOnode, pid uint32) (os.FileInfo, error) {

	log.Printf("Executing Lookup() method on %v handler", h.Name)

	// Identify the pidNsInode corresponding to this pid.
	pidInode := h.Service.FindPidNsInode(pid)
	if pidInode == 0 {
		return nil, errors.New("Could not identify pidNsInode")
	}

	return n.Stat()
}

func (h *ProcDiskstatsHandler) Getattr(n domain.IOnode, pid uint32) (*syscall.Stat_t, error) {

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

func (h *ProcDiskstatsHandler) Open(n domain.IOnode) error {

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

func (h *ProcDiskstatsHandler) Close(n domain.IOnode) error {

	log.Printf("Executing Close() method on %v handler", h.Name)

	return nil
}

func (h *ProcDiskstatsHandler) Read(n domain.IOnode, pid uint32,
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

func (h *ProcDiskstatsHandler) Write(n domain.IOnode, pid uint32,
	buf []byte) (int, error) {

	return 0, nil
}

func (h *ProcDiskstatsHandler) ReadDirAll(n domain.IOnode,
	pid uint32) ([]os.FileInfo, error) {

	return nil, nil
}

func (h *ProcDiskstatsHandler) GetName() string {
	return h.Name
}

func (h *ProcDiskstatsHandler) GetPath() string {
	return h.Path
}

func (h *ProcDiskstatsHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *ProcDiskstatsHandler) GetService() domain.HandlerService {
	return h.Service
}

func (h *ProcDiskstatsHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *ProcDiskstatsHandler) SetService(hs domain.HandlerService) {
	h.Service = hs
}
