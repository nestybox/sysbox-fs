package implementations

import (
	"io"
	"log"

	"github.com/nestybox/sysvisor/sysvisor-fs/domain"
)

//
// /proc/sys Handler
//
type ProcSysHandler struct {
	Name    string
	Path    string
	Enabled bool
	Service domain.HandlerService
}

func (h *ProcSysHandler) Open(node domain.IOnode) error {

	log.Printf("Executing %v open() method", h.Name)

	return nil
}

func (h *ProcSysHandler) Read(
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

func (h *ProcSysHandler) Write(
	node domain.IOnode,
	pidInode domain.Inode,
	buf []byte) (int, error) {

	return 0, nil
}

func (h *ProcSysHandler) GetName() string {
	return h.Name
}

func (h *ProcSysHandler) GetPath() string {
	return h.Path
}

func (h *ProcSysHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *ProcSysHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *ProcSysHandler) SetService(hs domain.HandlerService) {
	h.Service = hs
}
