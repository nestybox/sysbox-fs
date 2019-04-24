package implementations

import (
	"errors"
	"io"
	"log"
	"strconv"
	"strings"
	"syscall"

	"github.com/nestybox/sysvisor/sysvisor-fs/domain"
)

//
// /proc/sys/net/ipv6/conf/all/disable_ipv6 Handler
//
type DisableIPv6Handler struct {
	Name    string
	Path    string
	Enabled bool
	Service domain.HandlerService
}

func (h *DisableIPv6Handler) Open(node domain.IOnode) error {

	log.Printf("Executing %v open() method", h.Name)

	flags := node.GetOpenFlags()
	if flags != syscall.O_RDONLY && flags != syscall.O_WRONLY {
		return errors.New("/proc/sys/net/ipv6/conf/all/disable_ipv6: Permission denied")
	}

	if err := node.Open(); err != nil {
		log.Printf("Error opening file %v\n", h.Path)
		return errors.New("Error opening file")
	}

	return nil
}

func (h *DisableIPv6Handler) Read(
	node domain.IOnode,
	pidInode domain.Inode,
	buf []byte,
	off int64) (int, error) {

	log.Println("Executing %v read() method", h.Name)

	if off > 0 {
		return 0, io.EOF
	}

	//
	// Find the container-state corresponding to the container hosting this
	// Pid.
	//
	css := h.Service.StateService()
	cntr := css.ContainerLookupByPid(pidInode)
	if cntr == nil {
		log.Printf("Could not find the container originating this request ",
			"(pidNsInode %v)\n", pidInode)
		return 0, errors.New("Container not found")
	}

	//
	// Check if this resource has been initialized for this container. Otherwise,
	// fetch the information from the host FS and store it accordingly within
	// the container struct.
	//
	_, ok := cntr.Data[h.Path]
	if !ok {
		content, err := h.fetch(node, cntr)
		if err != nil {
			return 0, err
		}

		disableIPv6Map := map[string]string{
			h.Name: content,
		}

		cntr.Data[h.Path] = disableIPv6Map
	}

	//
	// At this point, some container-state data must be available to serve this
	// request.
	//
	data, ok := cntr.Data[h.Path][h.Name]
	if !ok {
		log.Println("Unexpected error")
		return 0, io.EOF
	}

	data += "\n"
	copy(buf, data)
	length := len(data)
	buf = buf[:length]

	return length, nil
}

func (h *DisableIPv6Handler) Write(
	node domain.IOnode,
	pidInode domain.Inode,
	buf []byte) (int, error) {

	log.Printf("Executing %v write() method", h.Name)

	newVal := strings.TrimSpace(string(buf))
	newValInt, err := strconv.Atoi(newVal)
	if err != nil {
		log.Println("Unexpected error:", err)
		return 0, err
	}

	//
	// Find the container-state corresponding to the container hosting this
	// Pid.
	//
	css := h.Service.StateService()
	cntr := css.ContainerLookupByPid(pidInode)
	if cntr == nil {
		log.Printf("Could not find the container originating this request ",
			"(pidNsInode %v)\n", pidInode)
		return 0, errors.New("Container not found")
	}

	//
	// Check if this resource has been initialized for this container. If not,
	// push it to the host FS and store it within the container struct.
	//
	_, ok := cntr.Data[h.Path]
	if !ok {
		if err := h.push(node, cntr, newVal); err != nil {
			return 0, err
		}

		disableIPv6Map := map[string]string{
			h.Name: newVal,
		}
		cntr.Data[h.Path] = disableIPv6Map

		return len(buf), nil
	}

	// Obtain existing value stored/cached in this container struct.
	curVal, ok := cntr.Data[h.Path][h.Name]
	if !ok {
		log.Println("Unexpected error")
		return 0, errors.New("Unexpected error")
	}
	curValInt, err := strconv.Atoi(curVal)
	if err != nil {
		log.Println("Unexpected error:", err)
		return 0, err
	}

	//
	// If new value matches the existing one, then there's noting else to be
	// done here.
	//
	if newValInt == curValInt {
		return len(buf), nil
	}

	// Push new value to host FS.
	if err := h.push(node, cntr, newVal); err != nil {
		return 0, err
	}

	// Writing the new value into container-state struct.
	cntr.Data[h.Path][h.Name] = newVal

	return len(buf), nil
}

func (h *DisableIPv6Handler) fetch(
	node domain.IOnode,
	c *domain.Container) (string, error) {

	event := &nsenterEvent{
		Resource:  h.Path,
		Message:   readRequest,
		Content:   "",
		Pid:       c.InitPid,
		Namespace: []nsType{string(nsTypeNet)},
	}

	res, err := event.launch()
	if err != nil {
		return "", err
	}

	return res.Content, nil
}

func (h *DisableIPv6Handler) push(
	node domain.IOnode,
	c *domain.Container,
	newVal string) error {

	event := &nsenterEvent{
		Resource:  h.Path,
		Message:   writeRequest,
		Content:   newVal,
		Pid:       c.InitPid,
		Namespace: []nsType{string(nsTypeNet)},
	}

	if _, err := event.launch(); err != nil {
		return err
	}

	return nil
}

func (h *DisableIPv6Handler) GetName() string {
	return h.Name
}

func (h *DisableIPv6Handler) GetPath() string {
	return h.Path
}

func (h *DisableIPv6Handler) GetEnabled() bool {
	return h.Enabled
}

func (h *DisableIPv6Handler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *DisableIPv6Handler) SetService(hs domain.HandlerService) {
	h.Service = hs
}
