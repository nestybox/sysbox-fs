package implementations

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/nestybox/sysvisor/sysvisor-fs/domain"
)

//
// /proc/sys/net/netfilter/nf_conntrack_max handler
//
type NfConntrackMaxHandler struct {
	Name      string
	Path      string
	Enabled   bool
	Cacheable bool
	Service   domain.HandlerService
}

func (h *NfConntrackMaxHandler) Lookup(n domain.IOnode, pid uint32) (os.FileInfo, error) {

	log.Printf("Executing Lookup() method on %v handler", h.Name)

	// Identify the pidNsInode corresponding to this pid.
	pidInode := h.Service.FindPidNsInode(pid)
	if pidInode == 0 {
		return nil, errors.New("Could not identify pidNsInode")
	}

	return n.Stat()
}

func (h *NfConntrackMaxHandler) Getattr(n domain.IOnode, pid uint32) (*syscall.Stat_t, error) {

	log.Printf("Executing Getattr() method on %v handler", h.Name)

	commonHandler, ok := h.Service.FindHandler("commonHandler")
	if !ok {
		return nil, fmt.Errorf("No commonHandler found")
	}

	return commonHandler.Getattr(n, pid)
}

func (h *NfConntrackMaxHandler) Open(n domain.IOnode) error {

	log.Printf("Executing %v open() method\n", h.Name)

	flags := n.OpenFlags()
	if flags != syscall.O_RDONLY && flags != syscall.O_WRONLY {
		return fmt.Errorf("%v: Permission denied", h.Path)
	}

	// During 'writeOnly' accesses, we must grant read-write rights temporarily
	// to allow push() to carry out the expected 'write' operation, as well as a
	// 'read' one too.
	if flags == syscall.O_WRONLY {
		n.SetOpenFlags(syscall.O_RDWR)
	}

	if err := n.Open(); err != nil {
		log.Printf("Error opening file %v\n", h.Path)
		return errors.New("Error opening file")
	}

	return nil
}

func (h *NfConntrackMaxHandler) Close(n domain.IOnode) error {

	log.Printf("Executing Close() method on %v handler", h.Name)

	return nil
}

func (h *NfConntrackMaxHandler) Read(n domain.IOnode, pid uint32,
	buf []byte, off int64) (int, error) {

	log.Printf("Executing %v read() method\n", h.Name)

	// We are dealing with a single integer element being read, so we can save
	// some cycles by returning right away if offset is any higher than zero.
	if off > 0 {
		return 0, io.EOF
	}

	name := n.Name()
	path := n.Path()

	// Identify the pidNsInode corresponding to this pid.
	ios := h.Service.IOService()
	tmpNode := ios.NewIOnode("", strconv.Itoa(int(pid)), 0)
	pidInode, err := ios.PidNsInode(tmpNode)
	if err != nil {
		return 0, err
	}

	// Find the container-state corresponding to the container hosting this
	// Pid.
	css := h.Service.StateService()
	cntr := css.ContainerLookupByPid(pidInode)
	if cntr == nil {
		log.Printf("Could not find the container originating this request (pidNsInode %v)\n", pidInode)
		return 0, errors.New("Container not found")
	}

	// Check if this resource has been initialized for this container. Otherwise,
	// fetch the information from the host FS and store it accordingly within
	// the container struct.
	data, ok := cntr.Data(path, name)
	if !ok {
		data, err := h.FetchFile(n, cntr)
		if err != nil && err != io.EOF {
			return 0, err
		}

		cntr.SetData(path, name, data)
	}

	// At this point, some container-state data must be available to serve this
	// request.
	if data == "" {
		data, ok = cntr.Data(path, name)
		if !ok {
			log.Println("Unexpected error")
			return 0, io.EOF
		}
	}

	data += "\n"
	copy(buf, data)
	length := len(data)
	buf = buf[:length]

	return length, nil
}

func (h *NfConntrackMaxHandler) Write(n domain.IOnode, pid uint32,
	buf []byte) (int, error) {

	log.Printf("Executing %v write() method\n", h.Name)

	name := n.Name()
	path := n.Path()

	newMax := strings.TrimSpace(string(buf))
	newMaxInt, err := strconv.Atoi(newMax)
	if err != nil {
		log.Println("Unexpected error:", err)
		return 0, err
	}

	// Identify the pidNsInode corresponding to this pid.
	ios := h.Service.IOService()
	tmpNode := ios.NewIOnode("", strconv.Itoa(int(pid)), 0)
	pidInode, err := ios.PidNsInode(tmpNode)
	if err != nil {
		return 0, err
	}

	// Find the container-state corresponding to the container hosting this
	// Pid.
	css := h.Service.StateService()
	cntr := css.ContainerLookupByPid(pidInode)
	if cntr == nil {
		log.Printf("Could not find the container originating this request (pidNsInode %v)\n", pidInode)
		return 0, errors.New("Container not found")
	}

	// Check if this resource has been initialized for this container. If not,
	// push it to the host FS and store it within the container struct.
	curMax, ok := cntr.Data(path, name)
	if !ok {
		if err := h.PushFile(n, cntr, newMaxInt); err != nil {
			return 0, err
		}

		cntr.SetData(path, name, newMax)

		return len(buf), nil
	}

	curMaxInt, err := strconv.Atoi(curMax)
	if err != nil {
		log.Println("Unexpected error:", err)
		return 0, err
	}

	// If new value is lower/equal than the existing one, then let's update this
	// new value into the container struct and return here. Notice that we cannot
	// push this (lower-than-current) value into the host FS, as we could be
	// impacting other syscontainers.
	if newMaxInt <= curMaxInt {
		cntr.SetData(path, name, newMax)

		return len(buf), nil
	}

	// Push new value to host FS.
	if err := h.PushFile(n, cntr, newMaxInt); err != nil {
		return 0, io.EOF
	}

	// Writing the new value into container-state struct.
	cntr.SetData(path, name, newMax)

	return len(buf), nil
}

func (h *NfConntrackMaxHandler) ReadDirAll(n domain.IOnode, pid uint32) ([]os.FileInfo, error) {

	return nil, nil
}

func (h *NfConntrackMaxHandler) FetchFile(n domain.IOnode, c domain.ContainerIface) (string, error) {

	// Read from host FS to extract the existing nf_conntrack_max value.
	curHostMax, err := n.ReadLine()
	if err != nil && err != io.EOF {
		log.Printf("Could not read from file %v\n", h.Path)
		return "", err
	}

	// High-level verification to ensure that format is the expected one.
	_, err = strconv.Atoi(curHostMax)
	if err != nil {
		log.Printf("Unexpected content read from file %v, error %v", h.Path, err)
		return "", err
	}

	return curHostMax, nil
}

func (h *NfConntrackMaxHandler) PushFile(n domain.IOnode, c domain.ContainerIface,
	newMaxInt int) error {

	curHostMax, err := n.ReadLine()
	if err != nil && err != io.EOF {
		return err
	}
	curHostMaxInt, err := strconv.Atoi(curHostMax)
	if err != nil {
		log.Println("Unexpected error:", err)
		return err
	}

	// If the existing host FS value is larger than the new one to configure,
	// then let's just return here as we want to keep the largest value
	// in the host FS.
	if newMaxInt <= curHostMaxInt {
		return nil
	}

	// Rewinding file offset back to its start point.
	_, err = n.SeekReset()
	if err != nil {
		log.Printf("Could not reset file offset: %v\n", err)
		return err
	}

	// Push down to host FS the new (larger) value.
	msg := []byte(strconv.Itoa(newMaxInt))
	_, err = n.Write(msg)
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

func (h *NfConntrackMaxHandler) GetService() domain.HandlerService {
	return h.Service
}

func (h *NfConntrackMaxHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *NfConntrackMaxHandler) SetService(hs domain.HandlerService) {
	h.Service = hs
}
