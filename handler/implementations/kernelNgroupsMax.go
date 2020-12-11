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
	"syscall"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
)

//
// /proc/sys/kernel/ngroups_max handler
//
// Documentation: The numerical value stored in this file represents the maximum
// number of supplementary groups of which a process can be a member of (65k in
// kernels 2.2+). This is a system-wide number and does not appear to be
// re-configurable at runtime, so we will proceed to cache its value on a
// per-container basis.
//
// Notice that this resource is perfectly reachable within a regular or system
// container. That's to say that our main purpose here is not 'functional'; we
// we are creating this handler to enhance sysbox-fs performance: every 'sudo'
// instruction does two consecutive reads() over this resource -- and that
// entails the execution of all the other file-operations too (i.e. lookup,
// getattr, etc).
//

type KernelNgroupsMaxHandler struct {
	domain.HandlerBase
}

func (h *KernelNgroupsMaxHandler) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method on %v handler", h.Name)

	return n.Stat()
}

func (h *KernelNgroupsMaxHandler) Getattr(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (*syscall.Stat_t, error) {

	logrus.Debugf("Executing Getattr() method on %v handler", h.Name)

	return nil, nil
}

func (h *KernelNgroupsMaxHandler) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	logrus.Debugf("Executing %v Open() method\n", h.Name)

	flags := n.OpenFlags()
	if flags != syscall.O_RDONLY {
		return fuse.IOerror{Code: syscall.EACCES}
	}

	if err := n.Open(); err != nil {
		logrus.Debugf("Error opening file %v", h.Path)
		return fuse.IOerror{Code: syscall.EIO}
	}

	return nil
}

func (h *KernelNgroupsMaxHandler) Close(n domain.IOnodeIface) error {

	logrus.Debugf("Executing Close() method on %v handler", h.Name)

	if err := n.Close(); err != nil {
		logrus.Debugf("Error closing file %v", h.Path)
		return fuse.IOerror{Code: syscall.EIO}
	}

	return nil
}

func (h *KernelNgroupsMaxHandler) Read(
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

	// Check if this resource has been initialized for this container. Otherwise,
	// fetch the information from the host FS and store it accordingly within
	// the container struct.
	cntr.Lock()
	data, ok := cntr.Data(path, name)
	if !ok {
		// Read from host FS to extract the existing 'ngroups_max' value.
		curHostVal, err := n.ReadLine()
		if err != nil && err != io.EOF {
			cntr.Unlock()
			logrus.Errorf("Could not read from file %v", h.Path)
			return 0, fuse.IOerror{Code: syscall.EIO}
		}

		// High-level verification to ensure that format is the expected one.
		_, err = strconv.Atoi(curHostVal)
		if err != nil {
			cntr.Unlock()
			logrus.Errorf("Unsupported content read from file %v, error %v", h.Path, err)
			return 0, fuse.IOerror{Code: syscall.EINVAL}
		}

		data = curHostVal
		cntr.SetData(path, name, data)
	}
	cntr.Unlock()

	data += "\n"

	return copyResultBuffer(req.Data, []byte(data))
}

func (h *KernelNgroupsMaxHandler) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing %v Write() method", h.Name)

	return 0, nil
}

func (h *KernelNgroupsMaxHandler) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	return nil, nil
}

func (h *KernelNgroupsMaxHandler) GetName() string {
	return h.Name
}

func (h *KernelNgroupsMaxHandler) GetPath() string {
	return h.Path
}

func (h *KernelNgroupsMaxHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *KernelNgroupsMaxHandler) GetType() domain.HandlerType {
	return h.Type
}

func (h *KernelNgroupsMaxHandler) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *KernelNgroupsMaxHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *KernelNgroupsMaxHandler) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
