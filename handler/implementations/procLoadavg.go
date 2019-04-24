package implementations

import (
	"io"
	"log"

	"github.com/nestybox/sysvisor/sysvisor-fs/domain"
)

//
// /proc/loadavg Handler
//
type ProcLoadavgHandler struct {
	Name    string
	Path    string
	Enabled bool
	Service domain.HandlerService
}

func (h *ProcLoadavgHandler) Open(node domain.IOnode) error {

	log.Printf("Executing %v open() method", h.Name)

	return nil
}

func (h *ProcLoadavgHandler) Read(
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

func (h *ProcLoadavgHandler) Write(
	node domain.IOnode,
	pidInode domain.Inode,
	buf []byte) (int, error) {

	return 0, nil
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
