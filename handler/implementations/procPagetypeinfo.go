package implementations

import (
	"io"
	"log"

	"github.com/nestybox/sysvisor/sysvisor-fs/domain"
)

//
// /proc/pagetypeinfo Handler
//
type ProcPagetypeinfoHandler struct {
	Name    string
	Path    string
	Enabled bool
	Service domain.HandlerService
}

func (h *ProcPagetypeinfoHandler) Open(node domain.IOnode) error {

	log.Printf("Executing %v open() method", h.Name)

	return nil
}

func (h *ProcPagetypeinfoHandler) Read(
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

func (h *ProcPagetypeinfoHandler) Write(
	node domain.IOnode,
	pidInode domain.Inode,
	buf []byte) (int, error) {

	return 0, nil
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
