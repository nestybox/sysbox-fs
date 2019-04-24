package implementations

import (
	"io"
	"log"

	"github.com/nestybox/sysvisor/sysvisor-fs/domain"
)

//
// /proc/stat Handler
//
type ProcStatHandler struct {
	Name    string
	Path    string
	Enabled bool
	Service domain.HandlerService
}

func (h *ProcStatHandler) Open(node domain.IOnode) error {

	log.Printf("Executing %v open() method", h.Name)

	return nil
}

func (h *ProcStatHandler) Read(
	node domain.IOnode,
	pidInode domain.Inode,
	buf []byte,
	off int64) (int, error) {

	log.Printf("Executing %v read() method", h.Name)

	if off > 0 {
		return 0, io.EOF
	}

	return 0, nil
}

func (h *ProcStatHandler) Write(
	node domain.IOnode,
	pidInode domain.Inode,
	buf []byte) (int, error) {

	return 0, nil
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

func (h *ProcStatHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *ProcStatHandler) SetService(hs domain.HandlerService) {
	h.Service = hs
}
