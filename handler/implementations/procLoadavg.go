package implementations

import (
	"io"
	"log"
	"os"

	"github.com/nestybox/sysvisor/sysvisor-fs/domain"
)

//
// /proc/loadavg Handler
//
type ProcLoadavgHandler struct {
	Name      string
	Path      string
	Enabled   bool
	Cacheable bool
	Service   domain.HandlerService
}

func (h *ProcLoadavgHandler) Lookup(n domain.IOnode, pid uint32) (os.FileInfo, error) {

	log.Printf("Executing Lookup() method on %v handler", h.Name)

	return os.Stat(n.Path())
}

func (h *ProcLoadavgHandler) Open(n domain.IOnode) error {

	log.Printf("Executing %v open() method", h.Name)

	return nil
}

func (h *ProcLoadavgHandler) Close(n domain.IOnode) error {

	log.Printf("Executing Close() method on %v handler", h.Name)

	return nil
}

func (h *ProcLoadavgHandler) Read(n domain.IOnode, pid uint32,
	buf []byte, off int64) (int, error) {

	log.Printf("Executing %v read() method", h.Name)

	if off > 0 {
		return 0, io.EOF
	}

	return 0, nil
}

func (h *ProcLoadavgHandler) Write(n domain.IOnode, pid uint32,
	buf []byte) (int, error) {

	return 0, nil
}

func (h *ProcLoadavgHandler) ReadDirAll(n domain.IOnode,
	pid uint32) ([]os.FileInfo, error) {

	return nil, nil
}

func (h *ProcLoadavgHandler) GetName() string {
	return h.Name
}

func (h *ProcLoadavgHandler) GetPath() string {
	return h.Path
}

func (h *ProcLoadavgHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *ProcLoadavgHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *ProcLoadavgHandler) SetService(hs domain.HandlerService) {
	h.Service = hs
}
