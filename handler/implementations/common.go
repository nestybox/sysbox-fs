package implementations

import (
	"errors"
	"io"
	"log"
	"os"
	"strings"

	"github.com/nestybox/sysvisor/sysvisor-fs/domain"
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

func (h *CommonHandler) Open(node domain.IOnode) error {

	log.Printf("Executing Open() method on %v handler", h.Name)

	return nil
}

func (h *CommonHandler) Close(node domain.IOnode) error {

	log.Printf("Executing Close() method on %v handler", h.Name)

	return nil
}

func (h *CommonHandler) Read(n domain.IOnode, i domain.Inode, buf []byte, off int64) (int, error) {

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

	// Find the container-state corresponding to the container hosting this
	// Pid.
	css := h.Service.StateService()
	cntr := css.ContainerLookupByPid(i)
	if cntr == nil {
		log.Printf("Could not find the container originating this request (pidNsInode %v)\n", i)
		return 0, errors.New("Container not found")
	}

	if h.Cacheable {
		// Check if this resource has been initialized for this container. Otherwise,
		// fetch the information from the host FS and store it accordingly within
		// the container struct.
		result, ok := cntr.Data(path, name)
		if !ok {
			data, err := h.fetchFile(n, cntr)
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
		result, err = h.fetchFile(n, cntr)
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

func (h *CommonHandler) Write(n domain.IOnode, i domain.Inode, buf []byte) (int, error) {

	log.Printf("Executing Write() method on %v handler", h.Name)

	name := n.Name()
	path := n.Path()

	newContent := strings.TrimSpace(string(buf))

	// Find the container-state corresponding to the container hosting this
	// Pid.
	css := h.Service.StateService()
	cntr := css.ContainerLookupByPid(i)
	if cntr == nil {
		log.Printf("Could not find the container originating this request (pidNsInode %v)\n", i)
		return 0, errors.New("Container not found")
	}

	if h.Cacheable {
		// Check if this resource has been initialized for this container. If not,
		// push it to the host FS and store it within the container struct.
		curContent, ok := cntr.Data(path, name)
		if !ok {
			if err := h.push(n, cntr, newContent); err != nil {
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
		if err := h.push(n, cntr, newContent); err != nil {
			return 0, err
		}
	}

	return len(buf), nil
}

func (h *CommonHandler) ReadDirAll(n domain.IOnode, i domain.Inode) ([]os.FileInfo, error) {

	log.Printf("Executing ReadDirAll() method on %v handler", h.Name)

	// Find the container-state corresponding to the container hosting this
	// Pid.
	css := h.Service.StateService()
	cntr := css.ContainerLookupByPid(i)
	if cntr == nil {
		log.Printf("Could not find the container originating this request (pidNsInode %v)\n", i)
		return nil, errors.New("Container not found")
	}

	content, err := h.fetchDir(n, cntr)
	if err != nil {
		return nil, err
	}

	return content, nil
}

// Auxiliar method to fetch the content of any given file within a container.
func (h *CommonHandler) fetchFile(n domain.IOnode, c domain.ContainerIface) (string, error) {

	event := &nsenterEvent{
		Resource:  n.Path(),
		Pid:       c.InitPid(),
		Namespace: []nsType{string(nsTypeNet)},
		ReqMsg: &nsenterMessage{
			Type:    readFileRequest,
			Payload: n.Path(),
		},
	}

	// Launch nsenter-event to obtain file state within container
	// namespaces.
	err := event.launch()
	if err != nil {
		return "", err
	}

	return event.ResMsg.Payload.(string), nil
}

// Auxiliar method to fetch the content of any given folder within a container.
func (h *CommonHandler) fetchDir(n domain.IOnode, c domain.ContainerIface) ([]os.FileInfo, error) {

	event := &nsenterEvent{
		Resource:  n.Path(),
		Pid:       c.InitPid(),
		Namespace: []nsType{string(nsTypeNet)},
		ReqMsg: &nsenterMessage{
			Type:    readDirRequest,
			Payload: n.Path(),
		},
	}

	// Launch nsenter-event to obtain dir state within container
	// namespaces.
	err := event.launch()
	if err != nil {
		return nil, err
	}

	// Transform event-response payload into a FileInfo slice. Notice that to
	// convert []T1 struct to a []T2 one we must iterate through each element
	// and do the conversion one element at a time.
	dirEntries := event.ResMsg.Payload.([]nsenterDir)
	osFileEntries := make([]os.FileInfo, len(dirEntries))
	for i, v := range dirEntries {
		osFileEntries[i] = v
	}

	return osFileEntries, nil
}

// Auxiliar method to inject content into any given file within a container.
func (h *CommonHandler) push(n domain.IOnode, c domain.ContainerIface, s string) error {

	event := &nsenterEvent{
		Resource:  n.Path(),
		Pid:       c.InitPid(),
		Namespace: []nsType{string(nsTypeNet)},
		ReqMsg: &nsenterMessage{
			Type:    writeFileRequest,
			Payload: s,
		},
	}

	err := event.launch()
	if err != nil {
		return err
	}

	// TODO: Verify that the response itself is a non-error one.

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

func (h *CommonHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *CommonHandler) SetService(hs domain.HandlerService) {
	h.Service = hs
}
