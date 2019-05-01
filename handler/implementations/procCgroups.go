package implementations

import (
	"io"
	"log"
	"os"

	"github.com/nestybox/sysvisor/sysvisor-fs/domain"
)

//
// /proc/cgroups Handler
//
type ProcCgroupsHandler struct {
	Name      string
	Path      string
	Enabled   bool
	Cacheable bool
	Service   domain.HandlerService
}

func (h *ProcCgroupsHandler) Open(node domain.IOnode) error {

	log.Printf("Executing %v open() method", h.Name)

	return nil
}

func (h *ProcCgroupsHandler) Close(node domain.IOnode) error {

	log.Printf("Executing Close() method on %v handler", h.Name)

	return nil
}

func (h *ProcCgroupsHandler) Read(
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

func (h *ProcCgroupsHandler) Write(
	node domain.IOnode,
	pidInode domain.Inode,
	buf []byte) (int, error) {

	return 0, nil
}

func (h *ProcCgroupsHandler) ReadDirAll(
	node domain.IOnode,
	pidInode domain.Inode) ([]os.FileInfo, error) {

	return nil, nil
}

func (h *ProcCgroupsHandler) GetName() string {
	return h.Name
}

func (h *ProcCgroupsHandler) GetPath() string {
	return h.Path
}

func (h *ProcCgroupsHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *ProcCgroupsHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *ProcCgroupsHandler) SetService(hs domain.HandlerService) {
	h.Service = hs
}
