//
// Copyright 2019-2020 Nestybox, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package implementations

import (
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
)

//
// /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_close_wait handler
//
// Documentation: This value defines the maximum amount of time (in secs) that
// a network element will wait, after closing its tcp-connection-end (FIN already
// send), for its peer to also close his side of the connection (FIN not sent yet).
//
// During write() operations, the new value will be only pushed down to the host
// FS if this one is higher than the existing figure.
//

type NfConntrackTcpTimeoutCWaitHandler struct {
	Name      string
	Path      string
	Type      domain.HandlerType
	Enabled   bool
	Cacheable bool
	Service   domain.HandlerServiceIface
}

func (h *NfConntrackTcpTimeoutCWaitHandler) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method on %v handler", h.Name)

	return n.Stat()
}

func (h *NfConntrackTcpTimeoutCWaitHandler) Getattr(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (*syscall.Stat_t, error) {

	logrus.Debugf("Executing Getattr() method on %v handler", h.Name)

	return nil, nil
}

func (h *NfConntrackTcpTimeoutCWaitHandler) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	logrus.Debugf("Executing %v Open() method\n", h.Name)

	flags := n.OpenFlags()
	if flags != syscall.O_RDONLY && flags != syscall.O_WRONLY {
		return fuse.IOerror{Code: syscall.EACCES}
	}

	// During 'writeOnly' accesses, we must grant read-write rights temporarily
	// to allow push() to carry out the expected 'write' operation, as well as a
	// 'read' one too.
	if flags == syscall.O_WRONLY {
		n.SetOpenFlags(syscall.O_RDWR)
	}

	if err := n.Open(); err != nil {
		logrus.Debugf("Error opening file %v", h.Path)
		return fuse.IOerror{Code: syscall.EIO}
	}

	return nil
}

func (h *NfConntrackTcpTimeoutCWaitHandler) Close(n domain.IOnodeIface) error {

	logrus.Debugf("Executing Close() method on %v handler", h.Name)

	if err := n.Close(); err != nil {
		logrus.Debugf("Error closing file %v", h.Path)
		return fuse.IOerror{Code: syscall.EIO}
	}

	return nil
}

func (h *NfConntrackTcpTimeoutCWaitHandler) Read(
	n domain.IOnodeIface,
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

	var err error

	// Check if this resource has been initialized for this container. Otherwise,
	// fetch the information from the host FS and store it accordingly within
	// the container struct.
	data, ok := cntr.Data(path, name)
	if !ok {
		data, err = h.fetchFile(n, cntr)
		if err != nil && err != io.EOF {
			return 0, err
		}

		cntr.SetData(path, name, data)
	}

	data += "\n"

	return copyResultBuffer(req.Data, []byte(data))
}

func (h *NfConntrackTcpTimeoutCWaitHandler) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing %v Write() method", h.Name)

	name := n.Name()
	path := n.Path()
	cntr := req.Container

	newMax := strings.TrimSpace(string(req.Data))
	newMaxInt, err := strconv.Atoi(newMax)
	if err != nil {
		logrus.Errorf("Unexpected error: %v", err)
		return 0, err
	}

	// Ensure operation is generated from within a registered sys container.
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return 0, errors.New("Container not found")
	}

	// Check if this resource has been initialized for this container. If not,
	// push it to the host FS and store it within the container struct.
	curMax, ok := cntr.Data(path, name)
	if !ok {
		if err := h.pushFile(n, cntr, newMaxInt); err != nil {
			return 0, err
		}

		cntr.SetData(path, name, newMax)

		return len(req.Data), nil
	}

	curMaxInt, err := strconv.Atoi(curMax)
	if err != nil {
		logrus.Errorf("Unexpected error: %v", err)
		return 0, err
	}

	// If new value is lower/equal than the existing one, then let's update this
	// new value into the container struct and return here. Notice that we cannot
	// push this (lower-than-current) value into the host FS, as we could be
	// impacting other sys containers.
	if newMaxInt <= curMaxInt {
		cntr.SetData(path, name, newMax)

		return len(req.Data), nil
	}

	// Push new value to host FS.
	if err := h.pushFile(n, cntr, newMaxInt); err != nil {
		return 0, io.EOF
	}

	// Writing the new value into container-state struct.
	cntr.SetData(path, name, newMax)

	return len(req.Data), nil
}

func (h *NfConntrackTcpTimeoutCWaitHandler) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	return nil, nil
}

func (h *NfConntrackTcpTimeoutCWaitHandler) fetchFile(
	n domain.IOnodeIface,
	c domain.ContainerIface) (string, error) {

	// Read from host FS to extract the existing value.
	curHostMax, err := n.ReadLine()
	if err != nil && err != io.EOF {
		logrus.Errorf("Could not read from file %v", h.Path)
		return "", err
	}

	// High-level verification to ensure that format is the expected one.
	_, err = strconv.Atoi(curHostMax)
	if err != nil {
		logrus.Errorf("Unexpected content read from file %v, error %v", h.Path, err)
		return "", err
	}

	return curHostMax, nil
}

func (h *NfConntrackTcpTimeoutCWaitHandler) pushFile(n domain.IOnodeIface, c domain.ContainerIface,
	newMaxInt int) error {

	curHostMax, err := n.ReadLine()
	if err != nil && err != io.EOF {
		return err
	}
	curHostMaxInt, err := strconv.Atoi(curHostMax)
	if err != nil {
		logrus.Errorf("Unexpected error: %v", err)
		return err
	}

	// If the existing host FS value is larger than the new one to configure,
	// then let's just return here as we want to keep the largest value
	// in the host FS.
	if newMaxInt <= curHostMaxInt {
		return nil
	}

	// Push down to host FS the new (larger) value.
	msg := []byte(strconv.Itoa(newMaxInt))
	err = n.WriteFile(msg)
	if err != nil {
		logrus.Errorf("Could not write to file: %v", err)
		return err
	}

	return nil
}

func (h *NfConntrackTcpTimeoutCWaitHandler) GetName() string {
	return h.Name
}

func (h *NfConntrackTcpTimeoutCWaitHandler) GetPath() string {
	return h.Path
}

func (h *NfConntrackTcpTimeoutCWaitHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *NfConntrackTcpTimeoutCWaitHandler) GetType() domain.HandlerType {
	return h.Type
}

func (h *NfConntrackTcpTimeoutCWaitHandler) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *NfConntrackTcpTimeoutCWaitHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *NfConntrackTcpTimeoutCWaitHandler) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
