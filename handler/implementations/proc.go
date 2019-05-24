package implementations

import (
	"errors"
	"log"
	"os"
	"syscall"

	"github.com/nestybox/sysvisor/sysvisor-fs/domain"
)

//
// Due to the fact that sysvisor-fs' procfs is sourced at /proc/sys, there's no
// much this handler needs to do. This handler's purpose is to be able to manage
// operations associated to /proc bind-mounts such as cpuinfo, meminfo, etc).
//

//
// /proc Handler
//
type ProcHandler struct {
	Name      string
	Path      string
	Enabled   bool
	Cacheable bool
	Service   domain.HandlerService
}

func (h *ProcHandler) Lookup(n domain.IOnode, pid uint32) (os.FileInfo, error) {

	log.Printf("Executing Lookup() method on %v handler", h.Name)

	// Identify the pidNsInode corresponding to this pid.
	pidInode := h.Service.FindPidNsInode(pid)
	if pidInode == 0 {
		return nil, errors.New("Could not identify pidNsInode")
	}

	return n.Stat()
}

func (h *ProcHandler) Getattr(n domain.IOnode, pid uint32) (*syscall.Stat_t, error) {

	log.Printf("Executing Getattr() method on %v handler", h.Name)

	return nil, nil
}

func (h *ProcHandler) Open(node domain.IOnode) error {

	log.Printf("Executing %v open() method", h.Name)

	return nil
}

func (h *ProcHandler) Close(node domain.IOnode) error {

	log.Printf("Executing Close() method on %v handler", h.Name)

	return nil
}

func (h *ProcHandler) Read(n domain.IOnode, pid uint32,
	buf []byte, off int64) (int, error) {

	log.Printf("Executing %v read() method", h.Name)

	return 0, nil
}

func (h *ProcHandler) Write(n domain.IOnode, pid uint32,
	buf []byte) (int, error) {

	return 0, nil
}

func (h *ProcHandler) ReadDirAll(n domain.IOnode, pid uint32) ([]os.FileInfo, error) {

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

func (h *ProcHandler) GetService() domain.HandlerService {
	return h.Service
}

func (h *ProcHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *ProcHandler) SetService(hs domain.HandlerService) {
	h.Service = hs
}
