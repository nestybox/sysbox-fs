package implementations

import (
	"fmt"
	"io"
	"log"
	"os"
	"syscall"

	"github.com/nestybox/sysvisor/sysvisor-fs/domain"
)

//
// /proc/meminfo Handler
//
type ProcMeminfoHandler struct {
	Name      string
	Path      string
	Enabled   bool
	Cacheable bool
	Service   domain.HandlerService
}

func (h *ProcMeminfoHandler) Lookup(n domain.IOnode, pid uint32) (os.FileInfo, error) {

	log.Printf("Executing Lookup() method on %v handler", h.Name)

	return os.Stat(n.Path())
}

func (h *ProcMeminfoHandler) Getattr(n domain.IOnode, pid uint32) (*syscall.Stat_t, error) {

	log.Printf("Executing Getattr() method on %v handler", h.Name)

	// Let's refer to the commonHandler for this task.
	commonHandler, ok := h.Service.FindHandler("commonHandler")
	if !ok {
		return nil, fmt.Errorf("No commonHandler found")
	}

	return commonHandler.Getattr(n, pid)
}

func (h *ProcMeminfoHandler) Open(n domain.IOnode) error {

	log.Printf("Executing %v open() method", h.Name)

	return nil
}

func (h *ProcMeminfoHandler) Close(n domain.IOnode) error {

	log.Printf("Executing Close() method on %v handler", h.Name)

	return nil
}

func (h *ProcMeminfoHandler) Read(n domain.IOnode, pid uint32,
	buf []byte, off int64) (int, error) {

	log.Printf("Executing %v read() method", h.Name)

	if off > 0 {
		return 0, io.EOF
	}

	return 0, nil
}

func (h *ProcMeminfoHandler) Write(n domain.IOnode, pid uint32,
	buf []byte) (int, error) {

	return 0, nil
}

func (h *ProcMeminfoHandler) ReadDirAll(n domain.IOnode,
	pid uint32) ([]os.FileInfo, error) {

	return nil, nil
}

func (h *ProcMeminfoHandler) GetName() string {
	return h.Name
}

func (h *ProcMeminfoHandler) GetPath() string {
	return h.Path
}

func (h *ProcMeminfoHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *ProcMeminfoHandler) GetService() domain.HandlerService {
	return h.Service
}

func (h *ProcMeminfoHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *ProcMeminfoHandler) SetService(hs domain.HandlerService) {
	h.Service = hs
}
