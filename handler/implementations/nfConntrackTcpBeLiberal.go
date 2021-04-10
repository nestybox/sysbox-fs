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
	"math/rand"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
)

//
// /proc/sys/net/netfilter/nf_conntrack_tcp_be_liberal
//
// Documentation: https://www.kernel.org/doc/Documentation/networking/nf_conntrack-sysctl.txt
//
// nf_conntrack_tcp_be_liberal - BOOLEAN
// 	0 - disabled (default)
// 	not 0 - enabled
//
// 	Be conservative in what you do, be liberal in what you accept from others.
// 	If it's non-zero, we mark only out of window RST segments as INVALID.
//
// Taking into account that kernel's netfilter can either operate in one mode or
// the other, we opt for letting the liberal mode prevail if set within any sys-container.
//

type NfConntrackTcpLiberalHandler struct {
	domain.HandlerBase
}

func (h *NfConntrackTcpLiberalHandler) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method on %v handler", h.Name)

	return n.Stat()
}

func (h *NfConntrackTcpLiberalHandler) Getattr(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (*syscall.Stat_t, error) {

	logrus.Debugf("Executing Getattr() method on %v handler", h.Name)

	return nil, nil
}

func (h *NfConntrackTcpLiberalHandler) Open(
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

func (h *NfConntrackTcpLiberalHandler) Close(n domain.IOnodeIface) error {

	logrus.Debugf("Executing Close() method on %v handler", h.Name)

	if err := n.Close(); err != nil {
		logrus.Debugf("Error closing file %v", h.Path)
		return fuse.IOerror{Code: syscall.EIO}
	}

	return nil
}

func (h *NfConntrackTcpLiberalHandler) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	var err error

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
	cntr.Lock()
	data, ok := cntr.Data(path, name)
	if !ok {
		data, err = h.fetchFile(n, cntr)
		if err != nil && err != io.EOF {
			cntr.Unlock()
			return 0, err
		}

		cntr.SetData(path, name, data)
	}
	cntr.Unlock()

	data += "\n"

	return copyResultBuffer(req.Data, []byte(data))
}

func (h *NfConntrackTcpLiberalHandler) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing %v Write() method", h.Name)

	name := n.Name()
	path := n.Path()
	cntr := req.Container

	newVal := strings.TrimSpace(string(req.Data))
	newValInt, err := strconv.Atoi(newVal)
	if err != nil {
		logrus.Errorf("Unexpected error: %v", err)
		return 0, err
	}

	// Ensure that only boolean values are allowed.
	if newValInt != 0 && newValInt != 1 {
		return 0, fuse.IOerror{Code: syscall.EINVAL}
	}

	// Ensure operation is generated from within a registered sys container.
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return 0, errors.New("Container not found")
	}

	cntr.Lock()
	defer cntr.Unlock()

	// Check if this resource has been initialized for this container. If not,
	// push it to the host FS and store it within the container struct.
	curVal, ok := cntr.Data(path, name)
	if !ok {
		if err := h.pushFile(n, cntr, newValInt); err != nil {
			return 0, err
		}

		cntr.SetData(path, name, newVal)

		return len(req.Data), nil
	}

	curValInt, err := strconv.Atoi(curVal)
	if err != nil {
		logrus.Errorf("Unexpected error: %v", err)
		return 0, err
	}

	// If the new value is 0 or the same as the current value, then let's update
	// this new value into the container struct but not push it down to the
	// kernel.
	if newValInt == 0 || newValInt == curValInt {
		cntr.SetData(path, name, newVal)
		return len(req.Data), nil
	}

	// Push new value to the kernel.
	if err := h.pushFile(n, cntr, newValInt); err != nil {
		return 0, io.EOF
	}

	// Writing the new value into container-state struct.
	cntr.SetData(path, name, newVal)

	return len(req.Data), nil
}

func (h *NfConntrackTcpLiberalHandler) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	return nil, nil
}

func (h *NfConntrackTcpLiberalHandler) fetchFile(
	n domain.IOnodeIface,
	c domain.ContainerIface) (string, error) {

	// We need the per-resource lock since we are about to access the resource on
	// the host FS. See pushFile() for a full explanation.
	h.Lock.Lock()

	// Read from host FS to extract the existing value.
	curHostMax, err := n.ReadLine()
	if err != nil && err != io.EOF {
		h.Lock.Unlock()
		logrus.Errorf("Could not read from file %v", h.Path)
		return "", err
	}

	h.Lock.Unlock()

	// High-level verification to ensure that format is the expected one.
	_, err = strconv.Atoi(curHostMax)
	if err != nil {
		logrus.Errorf("Unexpected content read from file %v, error %v", h.Path, err)
		return "", err
	}

	return curHostMax, nil
}

func (h *NfConntrackTcpLiberalHandler) pushFile(
	n domain.IOnodeIface,
	c domain.ContainerIface,
	newVal int) error {

	// We need the per-resource lock since we are about to access the resource on
	// the host FS and multiple sys containers could be accessing that same
	// resource concurrently.
	//
	// But that's not sufficient. Some users may deploy sysbox inside a
	// privileged container, and thus can have multiple sysbox instances running
	// concurrently on the same host. If those sysbox instances write conflicting
	// values to a kernel resource that uses this handler (e.g., a sysctl under
	// /proc/sys), a race condition arises that could cause the value to be
	// written to not be the max across all instances.
	//
	// To reduce the chance of this ocurring, in addition to the per-resource
	// lock, we use a heuristic in which we read-after-write to verify the value
	// of the resource is larger or equal to the one we wrote. If it isn't, it
	// means some other agent on the host wrote a smaller value to the resource
	// after we wrote to it, so we must retry the write.
	//
	// When retrying, we wait a small but random amount of time to reduce the
	// chance of hitting the race condition again. And we retry a limited amount
	// of times.
	//
	// Note that this solution works well for resolving race conditions among
	// sysbox instances, but may not address race conditions with other host
	// agents that write to the same sysctl. That's because there is no guarantee
	// that the other host agent will read-after-write and retry as sysbox does.

	h.Lock.Lock()
	defer h.Lock.Unlock()

	retries := 5
	retryDelay := 100 // microsecs

	for i := 0; i < retries; i++ {

		curVal, err := n.ReadLine()
		if err != nil && err != io.EOF {
			return err
		}
		curValInt, err := strconv.Atoi(curVal)
		if err != nil {
			logrus.Errorf("Unexpected error: %v", err)
			return err
		}

		// If the existing host value is larger than the new one to configure,
		// then let's just return here as we want to keep the largest value
		// in the host kernel.

		// TODO: move this up to the caller for better readability

		if newVal <= curValInt {
			return nil
		}

		// When retrying, wait a random delay to reduce chances of a new collision
		if i > 0 {
			d := rand.Intn(retryDelay)
			time.Sleep(time.Duration(d) * time.Microsecond)
		}

		// Push down to host kernel the new (larger) value.
		msg := []byte(strconv.Itoa(newVal))
		err = n.WriteFile(msg)
		if err != nil && !h.Service.IgnoreErrors() {
			logrus.Errorf("Could not write %d to file: %s", newVal, err)
			return err
		}
	}

	return nil
}

func (h *NfConntrackTcpLiberalHandler) GetName() string {
	return h.Name
}

func (h *NfConntrackTcpLiberalHandler) GetPath() string {
	return h.Path
}

func (h *NfConntrackTcpLiberalHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *NfConntrackTcpLiberalHandler) GetType() domain.HandlerType {
	return h.Type
}

func (h *NfConntrackTcpLiberalHandler) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *NfConntrackTcpLiberalHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *NfConntrackTcpLiberalHandler) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
