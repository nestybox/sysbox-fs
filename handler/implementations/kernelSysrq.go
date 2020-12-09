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
// /proc/sys/kernel/sysrq
//
// Documentation: It is a ‘magical’ key combo you can hit which the kernel will
// respond to regardless of whatever else it is doing, unless it is completely
// locked up.
//
// Supported values:
//
// 0 - disable sysrq completely
//
// 1 - enable all functions of sysrq
//
// >1 - bitmask of allowed sysrq functions (see below for detailed function
// description):
//
//  2 =   0x2 - enable control of console logging level
//  4 =   0x4 - enable control of keyboard (SAK, unraw)
//  8 =   0x8 - enable debugging dumps of processes etc.
//  16 =  0x10 - enable sync command
//  32 =  0x20 - enable remount read-only
//  64 =  0x40 - enable signalling of processes (term, kill, oom-kill)
//  128 = 0x80 - allow reboot/poweroff
//  256 = 0x100 - allow nicing of all RT tasks
//
// Note: As this is a system-wide attribute, changes will be only made
// superficially (at sys-container level). IOW, the host FS value will be left
// untouched.
//

const (
	minSysrqVal = 0
	maxSysrqVal = 511
)

type KernelSysrqHandler struct {
	domain.HandlerBase
}

func (h *KernelSysrqHandler) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method on %v handler", h.Name)

	return n.Stat()
}

func (h *KernelSysrqHandler) Getattr(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (*syscall.Stat_t, error) {

	logrus.Debugf("Executing Getattr() method on %v handler", h.Name)

	return nil, nil
}

func (h *KernelSysrqHandler) Open(
	n domain.IOnodeIface,
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

func (h *KernelSysrqHandler) Close(n domain.IOnodeIface) error {

	logrus.Debugf("Executing Close() method on %v handler", h.Name)

	if err := n.Close(); err != nil {
		logrus.Debugf("Error closing file %v", h.Path)
		return fuse.IOerror{Code: syscall.EIO}
	}

	return nil
}

func (h *KernelSysrqHandler) Read(
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
	data, ok := cntr.Data(path, name)
	if !ok {
		// Read from host FS to extract the existing value.
		curHostVal, err := n.ReadLine()
		if err != nil && err != io.EOF {
			logrus.Errorf("Could not read from file %v", h.Path)
			return 0, fuse.IOerror{Code: syscall.EIO}
		}

		// High-level verification to ensure that format is the expected one.
		_, err = strconv.Atoi(curHostVal)
		if err != nil {
			logrus.Errorf("Unsupported content read from file %v, error %v", h.Path, err)
			return 0, fuse.IOerror{Code: syscall.EINVAL}
		}

		data = curHostVal
		cntr.SetData(path, name, data)
	}

	data += "\n"

	return copyResultBuffer(req.Data, []byte(data))
}

func (h *KernelSysrqHandler) Write(
	n domain.IOnodeIface,
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
	newValInt, err := strconv.ParseInt(newVal, 0, 64)
	if err != nil {
		return 0, fuse.IOerror{Code: syscall.EINVAL}
	}

	// Ensure that only proper values are allowed as per this resource's
	// supported values.
	if newValInt < minSysrqVal || newValInt > maxSysrqVal {
		return 0, fuse.IOerror{Code: syscall.EINVAL}
	}

	// Store the new value within the container struct.
	cntr.SetData(path, name, strconv.FormatInt(newValInt, 10))

	return len(req.Data), nil
}

func (h *KernelSysrqHandler) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	return nil, nil
}

func (h *KernelSysrqHandler) GetName() string {
	return h.Name
}

func (h *KernelSysrqHandler) GetPath() string {
	return h.Path
}

func (h *KernelSysrqHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *KernelSysrqHandler) GetType() domain.HandlerType {
	return h.Type
}

func (h *KernelSysrqHandler) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *KernelSysrqHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *KernelSysrqHandler) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
