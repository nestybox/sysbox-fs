package implementations

import (
	"errors"
	"io"
	"log"
	"os"
	"strings"
	"strconv"
	"syscall"

	"github.com/nestybox/sysvisor-fs/domain"
)

//
// Common Handler for all namespaced resources within /proc/sys subtree.
//
type CommonHandler struct {
	Name      string
	Path      string
	Enabled   bool
	Cacheable bool
	Service   domain.HandlerService
}

func (h *CommonHandler) Lookup(n domain.IOnode, pid uint32) (os.FileInfo, error) {

	log.Printf("Executing Lookup() method on %v handler", h.Name)

	// Identify the pidNsInode corresponding to this pid.
	pidInode := h.Service.FindPidNsInode(pid)
	if pidInode == 0 {
		return nil, errors.New("Could not identify pidNsInode")
	}

	// Find the container-state corresponding to the container hosting this
	// Pid.
	css := h.Service.StateService()
	cntr := css.ContainerLookupByPid(pidInode)
	if cntr == nil {
		log.Printf("Could not find the container originating this request (pidNsInode %v)\n", pidInode)
		return nil, errors.New("Could not find associated container")
	}

	// Create nsenterEvent to initiate interaction with container namespaces.
	nss := h.Service.NSenterService()
	event := nss.NewEvent(
		n.Path(),
		cntr.InitPid(),
		[]domain.NStype{
			string(domain.NStypeUser),
			string(domain.NStypePid),
			string(domain.NStypeNet),
			string(domain.NStypeIpc),
			string(domain.NStypeCgroup),
			string(domain.NStypeUts),
		},
		&domain.NSenterMessage{Type: domain.LookupRequest, Payload: n.Path()},
		nil,
	)

	// Launch nsenter-event.
	err := nss.LaunchEvent(event)
	if err != nil {
		return nil, err
	}

	// Obtain nsenter-event response.
	responseMsg := nss.ResponseEvent(event)
	if responseMsg.Type == domain.ErrorResponse {
		return nil, responseMsg.Payload.(error)
	}

	info := responseMsg.Payload.(domain.FileInfo)

	return info, nil
}

func (h *CommonHandler) Getattr(n domain.IOnode, pid uint32) (*syscall.Stat_t, error) {

	log.Printf("Executing Getattr() method on %v handler", h.Name)

	// Identify the pidNsInode corresponding to this pid.
	pidInode := h.Service.FindPidNsInode(pid)
	if pidInode == 0 {
		return nil, errors.New("Could not identify pidNsInode")
	}

	// Find the container-state corresponding to the container hosting this
	// Pid.
	css := h.GetService().StateService()
	cntr := css.ContainerLookupByPid(pidInode)
	if cntr == nil {
		log.Printf("Could not find the container originating this request (pidNsInode %v)\n", pidInode)
		return nil, errors.New("Could not find associated container")
	}

	stat := &syscall.Stat_t{
		Uid: cntr.UID(),
		Gid: cntr.GID(),
	}
	return stat, nil
}

func (h *CommonHandler) Open(n domain.IOnode, pid uint32) error {

	log.Printf("Executing Open() method on %v handler", h.Name)

	// Identify the pidNsInode corresponding to this pid.
	pidInode := h.Service.FindPidNsInode(pid)
	if pidInode == 0 {
		return errors.New("Could not identify pidNsInode")
	}

	// Find the container-state corresponding to the container hosting this
	// Pid.
	css := h.Service.StateService()
	cntr := css.ContainerLookupByPid(pidInode)
	if cntr == nil {
		log.Printf("Could not find the container originating this request (pidNsInode %v)\n", pidInode)
		return errors.New("Container not found")
	}

	// Create nsenterEvent to initiate interaction with container namespaces.
	nss := h.Service.NSenterService()
	event := nss.NewEvent(
		n.Path(),
		cntr.InitPid(),
		[]domain.NStype{
			string(domain.NStypeUser),
			string(domain.NStypePid),
			string(domain.NStypeNet),
			string(domain.NStypeIpc),
			string(domain.NStypeCgroup),
			string(domain.NStypeUts),
		},
		&domain.NSenterMessage{
			Type: domain.OpenFileRequest,
			Payload: strconv.Itoa(n.OpenFlags()),
		},
		nil,
	)

	// Launch nsenter-event.
	err := nss.LaunchEvent(event)
	if err != nil {
		return err
	}

	// Obtain nsenter-event response.
	responseMsg := nss.ResponseEvent(event)
	if responseMsg.Type == domain.ErrorResponse {
		return responseMsg.Payload.(error)
	}

	return nil
}

func (h *CommonHandler) Close(node domain.IOnode) error {

	log.Printf("Executing Close() method on %v handler", h.Name)

	return nil
}

func (h *CommonHandler) Read(n domain.IOnode, pid uint32, buf []byte, off int64) (int, error) {

	log.Printf("Executing Read() method on %v handler", h.Name)

	if off > 0 {
		return 0, io.EOF
	}

	name := n.Name()
	path := n.Path()

	var (
		result string
		err    error
	)

	// Identify the pidNsInode corresponding to this pid.
	pidInode := h.Service.FindPidNsInode(pid)
	if pidInode == 0 {
		return 0, errors.New("Could not identify pidNsInode")
	}

	// Find the container-state corresponding to the container hosting this
	// Pid.
	css := h.Service.StateService()
	cntr := css.ContainerLookupByPid(pidInode)
	if cntr == nil {
		log.Printf("Could not find the container originating this request (pidNsInode %v)\n", pidInode)
		return 0, errors.New("Container not found")
	}

	if h.Cacheable {
		// Check if this resource has been initialized for this container. Otherwise,
		// fetch the information from the host FS and store it accordingly within
		// the container struct.
		result, ok := cntr.Data(path, name)
		if !ok {
			data, err := h.FetchFile(n, cntr)
			if err != nil {
				return 0, err
			}

			cntr.SetData(path, name, data)
		}

		// At this point, there must be some container-state data available to
		// serve this request.
		if result == "" {
			result, ok = cntr.Data(path, name)
			if !ok {
				log.Println("Unexpected error")
				return 0, io.EOF
			}
		}

	} else {
		result, err = h.FetchFile(n, cntr)
		if err != nil {
			return 0, err
		}
	}

	result += "\n"
	copy(buf, result)
	length := len(result)
	buf = buf[:length]

	return length, nil
}

func (h *CommonHandler) Write(n domain.IOnode, pid uint32, buf []byte) (int, error) {

	log.Printf("Executing Write() method on %v handler", h.Name)

	name := n.Name()
	path := n.Path()

	newContent := strings.TrimSpace(string(buf))

	// Identify the pidNsInode corresponding to this pid.
	pidInode := h.Service.FindPidNsInode(pid)
	if pidInode == 0 {
		return 0, errors.New("Could not identify pidNsInode")
	}

	// Find the container-state corresponding to the container hosting this
	// Pid.
	css := h.Service.StateService()
	cntr := css.ContainerLookupByPid(pidInode)
	if cntr == nil {
		log.Printf("Could not find the container originating this request (pidNsInode %v)\n", pidInode)
		return 0, errors.New("Container not found")
	}

	if h.Cacheable {
		// Check if this resource has been initialized for this container. If not,
		// push it to the host FS and store it within the container struct.
		curContent, ok := cntr.Data(path, name)
		if !ok {
			if err := h.PushFile(n, cntr, newContent); err != nil {
				return 0, err
			}

			cntr.SetData(path, name, newContent)

			return len(buf), nil
		}

		// If new value matches the existing one, then there's noting else to be
		// done here.
		if newContent == curContent {
			return len(buf), nil
		}

		// Writing the new value into container-state struct.
		cntr.SetData(path, name, newContent)

	} else {
		// Push new value to host FS.
		if err := h.PushFile(n, cntr, newContent); err != nil {
			return 0, err
		}
	}

	return len(buf), nil
}

func (h *CommonHandler) ReadDirAll(n domain.IOnode, pid uint32) ([]os.FileInfo, error) {

	log.Printf("Executing ReadDirAll() method on %v handler", h.Name)

	// Identify the pidNsInode corresponding to this pid.
	pidInode := h.Service.FindPidNsInode(pid)
	if pidInode == 0 {
		return nil, errors.New("Could not identify pidNsInode")
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
	nss := h.Service.NSenterService()
	event := nss.NewEvent(
		n.Path(),
		cntr.InitPid(),
		[]domain.NStype{
			string(domain.NStypeUser),
			string(domain.NStypePid),
			string(domain.NStypeNet),
			string(domain.NStypeIpc),
			string(domain.NStypeCgroup),
			string(domain.NStypeUts),
		},
		&domain.NSenterMessage{Type: domain.ReadDirRequest, Payload: ""},
		nil,
	)

	// Launch nsenter-event.
	err := nss.LaunchEvent(event)
	if err != nil {
		return nil, err
	}

	// Obtain nsenter-event response.
	responseMsg := nss.ResponseEvent(event)
	if responseMsg.Type == domain.ErrorResponse {
		return nil, responseMsg.Payload.(error)
	}

	// Transform event-response payload into a FileInfo slice. Notice that to
	// convert []T1 struct to a []T2 one, we must iterate through each element
	// and do the conversion one element at a time.
	dirEntries := responseMsg.Payload.([]domain.FileInfo)
	osFileEntries := make([]os.FileInfo, len(dirEntries))
	for i, v := range dirEntries {
		osFileEntries[i] = v
	}

	// Obtain FileEntries corresponding to emulated resources that could
	// potentially live in this folder.
	osEmulatedFileEntries := h.EmulatedFilesInfo(n, pid)

	osFileEntries = append(osFileEntries, osEmulatedFileEntries...)

	return osFileEntries, nil
}

// Auxiliar routine to aid during ReadDirAll() execution.
func (h *CommonHandler) EmulatedFilesInfo(n domain.IOnode, pid uint32) []os.FileInfo {

	var emulatedResources []string
	var emulatedFilesInfo []os.FileInfo

	// Obtain a list of all the emulated resources falling within the current
	// directory.
	emulatedResources = h.Service.DirHandlerEntries(n.Path())

	// For every emulated resource, invoke its Lookup() handler to obtain
	// the information required to satisfy this ongoing readDirAll()
	// instruction.
	for _, handlerPath := range emulatedResources {

		// Lookup the associated handler within handler-DB.
		handler, ok := h.Service.FindHandler(handlerPath)
		if !ok {
			log.Printf("No supported handler for %v resource", handlerPath)
			return nil
		}

		// Create temporary ionode to represent handler-path.
		ios := h.Service.IOService()
		newIOnode := ios.NewIOnode("", handlerPath, 0)

		// Handler execution.
		info, err := handler.Lookup(newIOnode, pid)
		if err != nil {
			log.Println("Error while running Lookup(): ", err)
			return nil
		}

		emulatedFilesInfo = append(emulatedFilesInfo, info)
	}

	return emulatedFilesInfo
}

// Auxiliar method to fetch the content of any given file within a container.
func (h *CommonHandler) FetchFile(n domain.IOnode, c domain.ContainerIface) (string, error) {

	// Create nsenterEvent to initiate interaction with container namespaces.
	nss := h.Service.NSenterService()
	event := nss.NewEvent(
		n.Path(),
		c.InitPid(),
		[]domain.NStype{
			string(domain.NStypeUser),
			string(domain.NStypePid),
			string(domain.NStypeNet),
			string(domain.NStypeIpc),
			string(domain.NStypeCgroup),
			string(domain.NStypeUts),
		},
		&domain.NSenterMessage{Type: domain.ReadFileRequest, Payload: ""},
		nil)

	// Launch nsenter-event to obtain file state within container
	// namespaces.
	err := nss.LaunchEvent(event)
	if err != nil {
		return "", err
	}

	// Obtain nsenter-event response.
	responseMsg := nss.ResponseEvent(event)
	if responseMsg.Type == domain.ErrorResponse {
		return "", responseMsg.Payload.(error)
	}

	info := responseMsg.Payload.(string)

	return info, nil
}

// Auxiliar method to inject content into any given file within a container.
func (h *CommonHandler) PushFile(n domain.IOnode, c domain.ContainerIface, s string) error {

	// Create nsenterEvent to initiate interaction with container namespaces.
	nss := h.Service.NSenterService()
	event := nss.NewEvent(
		n.Path(),
		c.InitPid(),
		[]domain.NStype{
			string(domain.NStypeUser),
			string(domain.NStypePid),
			string(domain.NStypeNet),
			string(domain.NStypeIpc),
			string(domain.NStypeCgroup),
			string(domain.NStypeUts),
		},
		&domain.NSenterMessage{Type: domain.WriteFileRequest, Payload: s},
		nil)

	// Launch nsenter-event to write file state within container
	// namespaces.
	err := nss.LaunchEvent(event)
	if err != nil {
		return err
	}

	// Obtain nsenter-event response.
	responseMsg := nss.ResponseEvent(event)
	if responseMsg.Type == domain.ErrorResponse {
		return responseMsg.Payload.(error)
	}

	return nil
}

func (h *CommonHandler) GetName() string {
	return h.Name
}

func (h *CommonHandler) GetPath() string {
	return h.Path
}

func (h *CommonHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *CommonHandler) GetService() domain.HandlerService {
	return h.Service
}

func (h *CommonHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *CommonHandler) SetService(hs domain.HandlerService) {
	h.Service = hs
}
