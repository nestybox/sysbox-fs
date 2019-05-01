package implementations

import (
	"io"
	"log"
	"os"

	"github.com/nestybox/sysvisor/sysvisor-fs/domain"
)

//
// /proc/meminfo Handler
//
type ProcMeminfoHandler struct {
	Name      string
	Path      string
	Enabled   bool
	Cacheable bool
	Service   domain.HandlerService
}

func (h *ProcMeminfoHandler) Open(node domain.IOnode) error {

	log.Printf("Executing %v open() method", h.Name)

	return nil
}

func (h *ProcMeminfoHandler) Close(node domain.IOnode) error {

	log.Printf("Executing Close() method on %v handler", h.Name)

	return nil
}

func (h *ProcMeminfoHandler) Read(
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

func (h *ProcMeminfoHandler) Write(
	node domain.IOnode,
	pidInode domain.Inode,
	buf []byte) (int, error) {

	return 0, nil
}

func (h *ProcMeminfoHandler) ReadDirAll(
	node domain.IOnode,
	pidInode domain.Inode) ([]os.FileInfo, error) {

	return nil, nil
}

func (h *ProcMeminfoHandler) GetName() string {
	return h.Name
}

func (h *ProcMeminfoHandler) GetPath() string {
	return h.Path
}

func (h *ProcMeminfoHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *ProcMeminfoHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *ProcMeminfoHandler) SetService(hs domain.HandlerService) {
	h.Service = hs
}
