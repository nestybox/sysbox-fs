package implementations

import (
	"io"
	"log"
	"os"

	"github.com/nestybox/sysvisor/sysvisor-fs/domain"
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

	return os.Stat(n.Path())
}

func (h *ProcPagetypeinfoHandler) Open(n domain.IOnode) error {

	log.Printf("Executing %v open() method", h.Name)

	return nil
}

func (h *ProcPagetypeinfoHandler) Close(n domain.IOnode) error {

	log.Printf("Executing Close() method on %v handler", h.Name)

	return nil
}

func (h *ProcPagetypeinfoHandler) Read(n domain.IOnode, pid uint32,
	buf []byte, off int64) (int, error) {

	log.Printf("Executing %v read() method", h.Name)

	if off > 0 {
		return 0, io.EOF
	}

	return 0, nil
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

func (h *ProcPagetypeinfoHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *ProcPagetypeinfoHandler) SetService(hs domain.HandlerService) {
	h.Service = hs
}
