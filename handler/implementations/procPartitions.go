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

	log.Printf("Executing Lookup() method on %v handler", h.Name)

	return os.Stat(n.Path())
}

func (h *ProcPartitionsHandler) Getattr(n domain.IOnode, pid uint32) (*syscall.Stat_t, error) {

	log.Printf("Executing Getattr() method on %v handler", h.Name)

	// Let's refer to the commonHandler for this task.
	commonHandler, ok := h.Service.FindHandler("commonHandler")
	if !ok {
		return nil, fmt.Errorf("No commonHandler found")
	}

	return commonHandler.Getattr(n, pid)
}

func (h *ProcPartitionsHandler) Open(n domain.IOnode) error {

	log.Printf("Executing %v open() method", h.Name)

	return nil
}

func (h *ProcPartitionsHandler) Close(n domain.IOnode) error {

	log.Printf("Executing Close() method on %v handler", h.Name)

	return nil
}

func (h *ProcPartitionsHandler) Read(n domain.IOnode, pid uint32,
	buf []byte, off int64) (int, error) {

	log.Printf("Executing %v read() method", h.Name)

	if off > 0 {
		return 0, io.EOF
	}

	return 0, nil
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
