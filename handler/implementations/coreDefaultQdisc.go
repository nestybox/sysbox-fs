//
// Copyright: (C) 2020 Nestybox Inc.  All rights reserved.
//

package implementations

import (
	"errors"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
)

//
// /proc/sys/net/core/default_qdisc handler
//
// Documentation: The default queuing discipline to use for network devices.
// This allows overriding the default of pfifo_fast with an alternative. Since
// the default queuing discipline is created without additional parameters so
// is best suited to queuing disciplines that work well without configuration
// like stochastic fair queue (sfq), CoDel (codel) or fair queue CoDel
// (fq_codel). Don’t use queuing disciplines like Hierarchical Token Bucket or
// Deficit Round Robin which require setting up classes and bandwidths. Note
// that physical multiqueue interfaces still use mq as root qdisc, which in
// turn uses this default for its leaves. Virtual devices (like e.g. lo or
// veth) ignore this setting and instead default to noqueue. Default:
// pfifo_fast.
//
// Supported schedulers (https://github.com/torvalds/linux/blob/master/net/sched/Kconfig#L478):
//
// 	- "pfifo_fast"
//	- "fq"
//	- "fq_codel"
//	- "sfq"
//	- "pfifo_fast"
//
// Note: As this is a system-wide attribute with mutually-exclusive values,
// changes will be only made superficially (at sys-container level). IOW,
// the host FS value will be left untouched.
//

type CoreDefaultQdiscHandler struct {
	Name      string
	Path      string
	Type      domain.HandlerType
	Enabled   bool
	Cacheable bool
	Service   domain.HandlerService
}

func (h *CoreDefaultQdiscHandler) Lookup(
	n domain.IOnode,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method on %v handler", h.Name)

	return n.Stat()
}

func (h *CoreDefaultQdiscHandler) Getattr(
	n domain.IOnode,
	req *domain.HandlerRequest) (*syscall.Stat_t, error) {

	logrus.Debugf("Executing Getattr() method on %v handler", h.Name)

	return nil, nil
}

func (h *CoreDefaultQdiscHandler) Open(
	n domain.IOnode,
	req *domain.HandlerRequest) error {

	logrus.Debugf("Executing %v Open() method\n", h.Name)

	flags := n.OpenFlags()
	if flags != syscall.O_RDONLY && flags != syscall.O_WRONLY {
		return fuse.IOerror{Code: syscall.EACCES}
	}

	if err := n.Open(); err != nil {
		logrus.Debugf("Error opening file %v", h.Path)
		return fuse.IOerror{Code: syscall.EIO}
	}

	return nil
}

func (h *CoreDefaultQdiscHandler) Close(n domain.IOnode) error {

	logrus.Debugf("Executing Close() method on %v handler", h.Name)

	if err := n.Close(); err != nil {
		logrus.Debugf("Error closing file %v", h.Path)
		return fuse.IOerror{Code: syscall.EIO}
	}

	return nil
}

func (h *CoreDefaultQdiscHandler) Read(
	n domain.IOnode,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing %v Read() method", h.Name)

	// We are dealing with a single integer element being read, so we can save
	// some cycles by returning right away if offset is any higher than zero.
	if req.Offset > 0 {
		return 0, io.EOF
	}

	name := n.Name()
	path := n.Path()
	cntr := req.Container

	// Ensure operation is generated from within a registered sys container.
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return 0, errors.New("Container not found")
	}

	// Check if this resource has been initialized for this container. Otherwise,
	// fetch the information from the host FS and store it accordingly within
	// the container struct.
	data, ok := cntr.Data(path, name)
	if !ok {
		// Read from host FS to extract the existing value.
		curHostVal, err := n.ReadLine()
		if err != nil && err != io.EOF {
			logrus.Errorf("Could not read from file %v", h.Path)
			return 0, fuse.IOerror{Code: syscall.EIO}
		}

		data = curHostVal
		cntr.SetData(path, name, data)
	}

	data += "\n"

	return copyResultBuffer(req.Data, []byte(data))
}

func (h *CoreDefaultQdiscHandler) Write(
	n domain.IOnode,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing %v Write() method", h.Name)

	name := n.Name()
	path := n.Path()
	cntr := req.Container

	// Ensure operation is generated from within a registered sys container.
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return 0, errors.New("Container not found")
	}

	newVal := strings.TrimSpace(string(req.Data))

	// Only supported values must be accepted.
	switch newVal {
	case "fq":
	case "fq_codel":
	case "sfq":
	case "pfifo_fast":
	default:
		return 0, fuse.IOerror{Code: syscall.EINVAL}
	}

	// Store the new value within the container struct.
	cntr.SetData(path, name, newVal)

	return len(req.Data), nil
}

func (h *CoreDefaultQdiscHandler) ReadDirAll(
	n domain.IOnode,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	return nil, nil
}

func (h *CoreDefaultQdiscHandler) GetName() string {
	return h.Name
}

func (h *CoreDefaultQdiscHandler) GetPath() string {
	return h.Path
}

func (h *CoreDefaultQdiscHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *CoreDefaultQdiscHandler) GetType() domain.HandlerType {
	return h.Type
}

func (h *CoreDefaultQdiscHandler) GetService() domain.HandlerService {
	return h.Service
}

func (h *CoreDefaultQdiscHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *CoreDefaultQdiscHandler) SetService(hs domain.HandlerService) {
	h.Service = hs
}
