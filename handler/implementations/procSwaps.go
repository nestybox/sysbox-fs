package implementations

import (
	"io"
	"log"

	"github.com/nestybox/sysvisor/sysvisor-fs/domain"
)

//
// /proc/swaps Handler
//
type ProcSwapsHandler struct {
	Name    string
	Path    string
	Enabled bool
	Service domain.HandlerService
}

func (h *ProcSwapsHandler) Open(node domain.IOnode) error {

	log.Printf("Executing %v open() method", h.Name)

	return nil
}

func (h *ProcSwapsHandler) Read(
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

func (h *ProcSwapsHandler) Write(
	node domain.IOnode,
	pidInode domain.Inode,
	buf []byte) (int, error) {

	return 0, nil
}

func (h *ProcSwapsHandler) GetName() string {
	return h.Name
}

func (h *ProcSwapsHandler) GetPath() string {
	return h.Path
}

func (h *ProcSwapsHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *ProcSwapsHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *ProcSwapsHandler) SetService(hs domain.HandlerService) {
	h.Service = hs
}
