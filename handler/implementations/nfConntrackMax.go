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
// /proc/sys/net/netfilter/nf_conntrack_max handler
//
type NfConntrackMaxHandler struct {
	Name    string
	Path    string
	Enabled bool
	Service domain.HandlerService
}

func (h *NfConntrackMaxHandler) Open(node domain.IOnode) error {

	log.Printf("Executing %v open() method\n", h.Name)

	flags := node.GetOpenFlags()
	if flags != syscall.O_RDONLY && flags != syscall.O_WRONLY {
		return errors.New("/proc/sys/net/netfilter/nf_conntrack_max: Permission denied")
	}

	// During 'writeOnly' accesses, we must grant read-write rights temporarily
	// to allow push() to carry out the expected 'write' operation, as well as a
	// 'read' one too.
	if flags == syscall.O_WRONLY {
		node.SetOpenFlags(syscall.O_RDWR)
	}

	if err := node.Open(); err != nil {
		log.Printf("Error opening file %v\n", h.Path)
		return errors.New("Error opening file")
	}

	return nil
}

func (h *NfConntrackMaxHandler) Read(
	node domain.IOnode,
	pidInode domain.Inode,
	buf []byte,
	off int64) (int, error) {

	log.Printf("Executing %v read() method\n", h.Name)

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

		nfConntrackMaxMap := map[string]string{
			h.Name: content,
		}

		cntr.Data[h.Path] = nfConntrackMaxMap
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

func (h *NfConntrackMaxHandler) Write(
	node domain.IOnode,
	pidInode domain.Inode,
	buf []byte) (int, error) {

	log.Printf("Executing %v write() method\n", h.Name)

	newMax := strings.TrimSpace(string(buf))
	newMaxInt, err := strconv.Atoi(newMax)
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
		if err := h.push(node, cntr, newMaxInt); err != nil {
			return 0, err
		}

		nfConntrackMaxMap := map[string]string{
			h.Name: newMax,
		}
		cntr.Data[h.Path] = nfConntrackMaxMap

		return len(buf), nil
	}

	// Obtain existing value stored/cached in this container struct.
	curMax, ok := cntr.Data[h.Path][h.Name]
	if !ok {
		log.Println("Unexpected error")
		return 0, err
	}

	curMaxInt, err := strconv.Atoi(curMax)
	if err != nil {
		log.Println("Unexpected error:", err)
		return 0, err
	}

	//
	// If new value is lower/equal than the existing one, then let's update this
	// new value into the container struct and return here. Notice that we cannot
	// push this (lower-than-current) value into the host FS, as we could be
	// impacting other syscontainers.
	//
	if newMaxInt <= curMaxInt {
		cntr.Data[h.Path][h.Name] = newMax

		return len(buf), nil
	}

	// Push new value to host FS.
	if err := h.push(node, cntr, newMaxInt); err != nil {
		return 0, io.EOF
	}

	// Writing the new value into container-state struct.
	cntr.Data[h.Path][h.Name] = newMax

	return len(buf), nil
}

func (h *NfConntrackMaxHandler) fetch(
	node domain.IOnode,
	c *domain.Container) (string, error) {

	// Read from host FS to extract the existing nf_conntrack_max value.
	curHostMax := node.ReadLine()
	if curHostMax == "" {
		log.Printf("Could not read from file %v\n", h.Path)
		return "", errors.New("Could not read from file")
	}

	// High-level verification to ensure that format is the expected one.
	_, err := strconv.Atoi(curHostMax)
	if err != nil {
		log.Printf("Unexpected content read from file %v, error %v", h.Path, err)
		return "", err
	}

	return curHostMax, nil
}

func (h *NfConntrackMaxHandler) push(
	node domain.IOnode,
	c *domain.Container,
	newMaxInt int) error {

	curHostMax := node.ReadLine()
	curHostMaxInt, err := strconv.Atoi(curHostMax)
	if err != nil {
		log.Println("Unexpected error:", err)
		return err
	}

	//
	// If the existing host FS value is larger than the new one to configure,
	// then let's just return here as we want to keep the largest value
	// in the host FS.
	//
	if newMaxInt <= curHostMaxInt {
		return nil
	}

	// Rewdind file offset back to its start point.
	_, err = node.SeekReset()
	if err != nil {
		log.Printf("Could not reset file offset: %v\n", err)
		return err
	}

	// Push down to host FS the new (larger) value.
	msg := []byte(strconv.Itoa(newMaxInt))
	_, err = node.Write(msg)
	if err != nil {
		log.Printf("Could not write to file: %v\n", err)
	}

	return nil
}

func (h *NfConntrackMaxHandler) GetName() string {
	return h.Name
}

func (h *NfConntrackMaxHandler) GetPath() string {
	return h.Path
}

func (h *NfConntrackMaxHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *NfConntrackMaxHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *NfConntrackMaxHandler) SetService(hs domain.HandlerService) {
	h.Service = hs
}
