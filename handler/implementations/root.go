package implementations

import (
	"errors"
	"log"
	"os"
	"syscall"

	"github.com/nestybox/sysvisor/sysvisor-fs/domain"
)

//
// This handler's sole purpose is to prevent users in the host file-system from
// being able to list the file contents present in sysvisor-fs mountpoint. With
// the exception of lookup(), all operations in this handler will return nil.
// Notice that only users in the host FS can invoke this handler as sysvisor-fs
// is mounted in /proc and /proc/sys within system containers.
//

//
// / Handler
//
type RootHandler struct {
	Name      string
	Path      string
	Enabled   bool
	Cacheable bool
	Service   domain.HandlerService
}

func (h *RootHandler) Lookup(n domain.IOnode, pid uint32) (os.FileInfo, error) {

	log.Printf("Executing Lookup() method on %v handler", h.Name)

	// Identify the pidNsInode corresponding to this pid.
	pidInode := h.Service.FindPidNsInode(pid)
	if pidInode == 0 {
		return nil, errors.New("Could not identify pidNsInode")
	}

	return n.Stat()
}

func (h *RootHandler) Getattr(n domain.IOnode, pid uint32) (*syscall.Stat_t, error) {

	log.Printf("Executing Getattr() method on %v handler", h.Name)

	return nil, nil
}

func (h *RootHandler) Open(node domain.IOnode) error {

	log.Printf("Executing %v open() method", h.Name)

	return nil
}

func (h *RootHandler) Close(node domain.IOnode) error {

	log.Printf("Executing Close() method on %v handler", h.Name)

	return nil
}

func (h *RootHandler) Read(n domain.IOnode, pid uint32,
	buf []byte, off int64) (int, error) {

	log.Printf("Executing %v read() method", h.Name)

	return 0, nil
}

func (h *RootHandler) Write(n domain.IOnode, pid uint32,
	buf []byte) (int, error) {

	return 0, nil
}

func (h *RootHandler) ReadDirAll(n domain.IOnode, pid uint32) ([]os.FileInfo, error) {

	return nil, nil
}

func (h *RootHandler) GetName() string {
	return h.Name
}

func (h *RootHandler) GetPath() string {
	return h.Path
}

func (h *RootHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *RootHandler) GetService() domain.HandlerService {
	return h.Service
}

func (h *RootHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *RootHandler) SetService(hs domain.HandlerService) {
	h.Service = hs
}
