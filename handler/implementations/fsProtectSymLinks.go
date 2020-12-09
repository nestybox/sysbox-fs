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
// /proc/sys/fs/protected_symlinks handler
//
// Documentation: A long-standing class of security issues is the symlink-based
// time-of-check-time-of-use race, most commonly seen in world-writable
// directories like /tmp. The common method of exploitation of this flaw it to
// cross privilege boundaries when following a given symlink (i.e. a root process
// follows a symlink belonging to another user).
//
// Only two values are supported:
//
// - "0": symlink-following behavior is unrestricted.
//
// - "1": symlinks are permitted to be followed only when outside a sticky
// world-writable directory, or when the uid of the symlink and follower match,
// or when the directory owner matches the symlink’s owner.
//
type FsProtectSymLinksHandler struct {
	domain.HandlerBase
}

func (h *FsProtectSymLinksHandler) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method on %v handler", h.Name)

	return n.Stat()
}

func (h *FsProtectSymLinksHandler) Getattr(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (*syscall.Stat_t, error) {

	logrus.Debugf("Executing Getattr() method on %v handler", h.Name)

	return nil, nil
}

func (h *FsProtectSymLinksHandler) Open(
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

func (h *FsProtectSymLinksHandler) Close(n domain.IOnodeIface) error {

	logrus.Debugf("Executing Close() method on %v handler", h.Name)

	if err := n.Close(); err != nil {
		logrus.Debugf("Error closing file %v", h.Path)
		return fuse.IOerror{Code: syscall.EIO}
	}

	return nil
}

func (h *FsProtectSymLinksHandler) Read(
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

func (h *FsProtectSymLinksHandler) Write(
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
	newValInt, err := strconv.Atoi(newVal)
	if err != nil {
		return 0, fuse.IOerror{Code: syscall.EINVAL}
	}

	// Ensure that only proper values are allowed as per this resource's
	// supported values.
	if newValInt < 0 || newValInt > 1 {
		return 0, fuse.IOerror{Code: syscall.EINVAL}
	}

	// Store the new value within the container struct.
	cntr.SetData(path, name, newVal)

	return len(req.Data), nil
}

func (h *FsProtectSymLinksHandler) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	return nil, nil
}

func (h *FsProtectSymLinksHandler) GetName() string {
	return h.Name
}

func (h *FsProtectSymLinksHandler) GetPath() string {
	return h.Path
}

func (h *FsProtectSymLinksHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *FsProtectSymLinksHandler) GetType() domain.HandlerType {
	return h.Type
}

func (h *FsProtectSymLinksHandler) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *FsProtectSymLinksHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *FsProtectSymLinksHandler) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
