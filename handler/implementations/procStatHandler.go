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
// /proc/stat Handler
//
type ProcStatHandler struct {
	Name      string
	Path      string
	Enabled   bool
	Cacheable bool
	Service   domain.HandlerService
}

func (h *ProcStatHandler) Lookup(n domain.IOnode, pid uint32) (os.FileInfo, error) {

	log.Printf("Executing Lookup() method on %v handler", h.Name)

	return os.Stat(n.Path())
}

func (h *ProcStatHandler) Getattr(n domain.IOnode, pid uint32) (*syscall.Stat_t, error) {

	log.Printf("Executing Getattr() method on %v handler", h.Name)

	// Let's refer to the commonHandler for this task.
	commonHandler, ok := h.Service.FindHandler("commonHandler")
	if !ok {
		return nil, fmt.Errorf("No commonHandler found")
	}

	return commonHandler.Getattr(n, pid)
}

func (h *ProcStatHandler) Open(n domain.IOnode) error {

	log.Printf("Executing %v open() method", h.Name)

	return nil
}

func (h *ProcStatHandler) Close(n domain.IOnode) error {

	log.Printf("Executing Close() method on %v handler", h.Name)

	return nil
}

func (h *ProcStatHandler) Read(n domain.IOnode, pid uint32,
	buf []byte, off int64) (int, error) {

	log.Printf("Executing %v read() method", h.Name)

	if off > 0 {
		return 0, io.EOF
	}

	return 0, nil
}

func (h *ProcStatHandler) Write(n domain.IOnode, pid uint32,
	buf []byte) (int, error) {

	return 0, nil
}

func (h *ProcStatHandler) ReadDirAll(n domain.IOnode,
	pid uint32) ([]os.FileInfo, error) {

	return nil, nil
}

func (h *ProcStatHandler) GetName() string {
	return h.Name
}

func (h *ProcStatHandler) GetPath() string {
	return h.Path
}

func (h *ProcStatHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *ProcStatHandler) GetService() domain.HandlerService {
	return h.Service
}

func (h *ProcStatHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *ProcStatHandler) SetService(hs domain.HandlerService) {
	h.Service = hs
}
