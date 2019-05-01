package implementations

import (
	"errors"
	"log"
	"os"

	"github.com/nestybox/sysvisor/sysvisor-fs/domain"
)

//
// /proc/sys/net/netfilter directory handler.
//
type NetNetfilter struct {
	Name      string
	Path      string
	Enabled   bool
	Cacheable bool
	Service   domain.HandlerService
}

func (h *NetNetfilter) Open(node domain.IOnode) error {

	return nil
}

func (h *NetNetfilter) Close(node domain.IOnode) error {

	return nil
}

func (h *NetNetfilter) Read(n domain.IOnode, i domain.Inode,
	buf []byte, off int64) (int, error) {

	return 0, nil
}

func (h *NetNetfilter) Write(n domain.IOnode, i domain.Inode, buf []byte) (int, error) {

	return len(buf), nil
}

func (h *NetNetfilter) ReadDirAll(n domain.IOnode, i domain.Inode) ([]os.FileInfo, error) {

	log.Printf("Executing ReadDirAll() method on %v handler", h.Name)

	// Find the container-state corresponding to the container hosting this
	// Pid.
	css := h.Service.StateService()
	cntr := css.ContainerLookupByPid(i)
	if cntr == nil {
		log.Printf("Could not find the container originating this request (pidNsInode %v)\n", i)
		return nil, errors.New("Container not found")
	}

	// Instantiate and execute a commonHandler to serve the requested path.
	var commonHandler = &CommonHandler{
		Name:    h.Name,
		Path:    h.Path,
		Service: h.Service,
	}

	dirContent, err := commonHandler.ReadDirAll(n, i)
	if err != nil {
		return nil, err
	}

	// Create a fake dentry that can be appended to the info collected by
	// commonHandler.
	fakeFile := &nsenterDir{
		Dname: "nf_conntrack_max",
		Dsize: 0,
		// TODO: Replace this literal with a proper global-type.
		Dmode:    0644,
		DmodTime: cntr.Ctime,
		DisDir:   false,
	}

	dirContent = append(dirContent, fakeFile)

	return dirContent, nil
}

func (h *NetNetfilter) GetName() string {
	return h.Name
}

func (h *NetNetfilter) GetPath() string {
	return h.Path
}

func (h *NetNetfilter) GetEnabled() bool {
	return h.Enabled
}

func (h *NetNetfilter) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *NetNetfilter) SetService(hs domain.HandlerService) {
	h.Service = hs
}
