package implementations

import (
	"io"
	"log"

	"github.com/nestybox/sysvisor/sysvisor-fs/domain"
)

//
// /proc/cgroups Handler
//
type ProcDevicesHandler struct {
	Name    string
	Path    string
	Enabled bool
	Service domain.HandlerService
}

func (h *ProcDevicesHandler) Open(node domain.IOnode) error {

	log.Printf("Executing %v open() method", h.Name)

	return nil
}

func (h *ProcDevicesHandler) Read(
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

func (h *ProcDevicesHandler) Write(
	node domain.IOnode,
	pidInode domain.Inode,
	buf []byte) (int, error) {

	return 0, nil
}

func (h *ProcDevicesHandler) GetName() string {
	return h.Name
}

func (h *ProcDevicesHandler) GetPath() string {
	return h.Path
}

func (h *ProcDevicesHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *ProcDevicesHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *ProcDevicesHandler) SetService(hs domain.HandlerService) {
	h.Service = hs
}
