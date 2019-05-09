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
// /proc/cpuinfo Handler
//
type ProcCpuinfoHandler struct {
	Name      string
	Path      string
	Enabled   bool
	Cacheable bool
	Service   domain.HandlerService
}

func (h *ProcCpuinfoHandler) Lookup(n domain.IOnode, pid uint32) (os.FileInfo, error) {

	log.Printf("Executing Lookup() method on %v handler", h.Name)

	return os.Stat(n.Path())
}

func (h *ProcCpuinfoHandler) Getattr(n domain.IOnode, pid uint32) (*syscall.Stat_t, error) {

	log.Printf("Executing Getattr() method on %v handler", h.Name)

	commonHandler, ok := h.Service.FindHandler("commonHandler")
	if !ok {
		return nil, fmt.Errorf("No commonHandler found")
	}

	return commonHandler.Getattr(n, pid)
}

func (h *ProcCpuinfoHandler) Open(node domain.IOnode) error {

	log.Printf("Executing %v open() method", h.Name)

	return nil
}

func (h *ProcCpuinfoHandler) Close(node domain.IOnode) error {

	log.Printf("Executing Close() method on %v handler", h.Name)

	return nil
}

func (h *ProcCpuinfoHandler) Read(n domain.IOnode, pid uint32,
	buf []byte, off int64) (int, error) {

	log.Printf("Executing %v read() method", h.Name)

	if off > 0 {
		return 0, io.EOF
	}

	return 0, nil
}

func (h *ProcCpuinfoHandler) Write(n domain.IOnode, pid uint32,
	buf []byte) (int, error) {

	return 0, nil
}

func (h *ProcCpuinfoHandler) ReadDirAll(n domain.IOnode, pid uint32) ([]os.FileInfo, error) {

	return nil, nil
}

func (h *ProcCpuinfoHandler) GetName() string {
	return h.Name
}

func (h *ProcCpuinfoHandler) GetPath() string {
	return h.Path
}

func (h *ProcCpuinfoHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *ProcCpuinfoHandler) GetService() domain.HandlerService {
	return h.Service
}

func (h *ProcCpuinfoHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *ProcCpuinfoHandler) SetService(hs domain.HandlerService) {
	h.Service = hs
}
