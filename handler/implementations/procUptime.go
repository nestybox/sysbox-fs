package implementations

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/nestybox/sysvisor/sysvisor-fs/domain"
)

//
// /proc/uptime Handler
//
type ProcUptimeHandler struct {
	Name      string
	Path      string
	Enabled   bool
	Cacheable bool
	Service   domain.HandlerService
}

func (h *ProcUptimeHandler) Open(n domain.IOnode) error {

	log.Printf("Executing %v open() method", h.Name)

	flags := n.OpenFlags()
	if flags != syscall.O_RDONLY {
		return fmt.Errorf("%v: Permission denied", h.Path)
	}

	if err := n.Open(); err != nil {
		log.Printf("Error opening file %v\n", h.Path)
		return fmt.Errorf("Error opening file %v", h.Path)
	}

	return nil
}

func (h *ProcUptimeHandler) Close(n domain.IOnode) error {

	log.Printf("Executing Close() method on %v handler", h.Name)

	return nil
}

func (h *ProcUptimeHandler) Read(n domain.IOnode, i domain.Inode, buf []byte, off int64) (int, error) {

	log.Printf("Executing %v read() method", h.Name)

	if off > 0 {
		return 0, io.EOF
	}

	//
	// Find the container-state corresponding to the container hosting this
	// Pid.
	//
	css := h.Service.StateService()
	cntr := css.ContainerLookupByPid(i)
	if cntr == nil {
		log.Printf("Could not find the container originating this request (pidNsInode %v)\n", i)
		return 0, errors.New("Container not found")
	}

	//
	// We can assume that by the time a user generates a request to read
	// /proc/uptime, the embedding container has been fully initialized,
	// so cs.ctime is already holding a valid value.
	//
	data := cntr.Ctime()

	// Calculate container's uptime.
	uptime := time.Now().Unix() - data.Unix()
	uptimeStr := strconv.FormatInt(uptime, 10)

	//
	// TODO: Notice that we are dumping the same values into the two columns
	// expected in /proc/uptime. The value utilized for the first column is
	// an accurate one (uptime seconds), however, the second one is just
	// an approximation.
	//
	res := uptimeStr + " " + uptimeStr + "\n"
	copy(buf, res)
	buf = buf[:len(res)]

	return len(buf), nil
}

func (h *ProcUptimeHandler) Write(n domain.IOnode, i domain.Inode, buf []byte) (int, error) {

	return 0, nil
}

func (h *ProcUptimeHandler) ReadDirAll(n domain.IOnode, i domain.Inode) ([]os.FileInfo, error) {

	return nil, nil
}

func (h *ProcUptimeHandler) GetName() string {

	return h.Name
}

func (h *ProcUptimeHandler) GetPath() string {

	return h.Path
}

func (h *ProcUptimeHandler) GetEnabled() bool {

	return h.Enabled
}

func (h *ProcUptimeHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *ProcUptimeHandler) SetService(hs domain.HandlerService) {

	h.Service = hs
}
