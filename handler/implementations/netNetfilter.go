package implementations

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"syscall"

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

func (h *NetNetfilter) Lookup(n domain.IOnode, pid uint32) (os.FileInfo, error) {

	log.Printf("Executing Lookup() method on %v handler", h.Name)

	// Identify the pidNsInode corresponding to this pid.
	ios := h.Service.IOService()
	tmpNode := ios.NewIOnode("", strconv.Itoa(int(pid)), 0)
	pidInode, err := ios.PidNsInode(tmpNode)
	if err != nil {
		return nil, err
	}

	// Find the container-state corresponding to the container hosting this
	// Pid.
	css := h.Service.StateService()
	cntr := css.ContainerLookupByPid(pidInode)
	if cntr == nil {
		log.Printf("Could not find the container originating this request (pidNsInode %v)\n", pidInode)
		return nil, errors.New("Container not found")
	}

	// Create nsenterEvent to initiate interaction with container namespaces.
	event := &nsenterEvent{
		Resource:  n.Path(),
		Pid:       cntr.InitPid(),
		Namespace: []nsType{string(nsTypeNet)},
		ReqMsg: &nsenterMessage{
			Type:    lookupRequest,
			Payload: n.Path(),
		},
	}

	// Launch nsenter-event.
	err = event.launch()
	if err != nil {
		return nil, err
	}

	// Dereference received FileInfo payload.
	info := event.ResMsg.Payload.(domain.FileInfo)

	return info, nil
}

func (h *NetNetfilter) Getattr(n domain.IOnode, pid uint32) (*syscall.Stat_t, error) {

	log.Printf("Executing Getattr() method on %v handler", h.Name)

	commonHandler, ok := h.Service.FindHandler("commonHandler")
	if !ok {
		return nil, fmt.Errorf("No commonHandler found")
	}

	return commonHandler.Getattr(n, pid)
}

func (h *NetNetfilter) Open(node domain.IOnode) error {

	return nil
}

func (h *NetNetfilter) Close(node domain.IOnode) error {

	return nil
}

func (h *NetNetfilter) Read(n domain.IOnode, pid uint32,
	buf []byte, off int64) (int, error) {

	return 0, nil
}

func (h *NetNetfilter) Write(n domain.IOnode, pid uint32, buf []byte) (int, error) {

	return len(buf), nil
}

func (h *NetNetfilter) ReadDirAll(n domain.IOnode, pid uint32) ([]os.FileInfo, error) {

	log.Printf("Executing ReadDirAll() method on %v handler", h.Name)

	// Identify the pidNsInode corresponding to this pid.
	ios := h.Service.IOService()
	tmpNode := ios.NewIOnode("", strconv.Itoa(int(pid)), 0)
	pidInode, err := ios.PidNsInode(tmpNode)
	if err != nil {
		return nil, err
	}

	// Find the container-state corresponding to the container hosting this
	// Pid.
	css := h.Service.StateService()
	cntr := css.ContainerLookupByPid(pidInode)
	if cntr == nil {
		log.Printf("Could not find the container originating this request (pidNsInode %v)\n", pidInode)
		return nil, errors.New("Container not found")
	}

	// Instantiate and execute a commonHandler to serve the requested path.
	var commonHandler = &CommonHandler{
		Name:    h.Name,
		Path:    h.Path,
		Service: h.Service,
	}

	dirContent, err := commonHandler.ReadDirAll(n, pid)
	if err != nil {
		return nil, err
	}

	// Create a fake dentry that can be appended to the info collected by
	// commonHandler.
	fakeFile := &domain.FileInfo{
		Fname: "nf_conntrack_max",
		Fsize: 0,
		// TODO: Replace this literal with a proper global-type.
		Fmode:    0644,
		FmodTime: cntr.Ctime(),
		FisDir:   false,
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

func (h *NetNetfilter) GetService() domain.HandlerService {
	return h.Service
}

func (h *NetNetfilter) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *NetNetfilter) SetService(hs domain.HandlerService) {
	h.Service = hs
}
