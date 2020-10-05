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
	"os"
	"syscall"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
)

//
// /proc/sys/net/ipv4/neigh/default directory handler
//
type NeighDefaultHandler struct {
	Name      string
	Path      string
	Type      domain.HandlerType
	Enabled   bool
	Cacheable bool
	Service   domain.HandlerServiceIface
}

func (h *NeighDefaultHandler) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method on %v handler", h.Name)

	return n.Stat()
}

func (h *NeighDefaultHandler) Getattr(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (*syscall.Stat_t, error) {

	logrus.Debugf("Executing Getattr() method for Req ID=%#x on %v handler", req.ID, h.Name)

	// Ensure operation is generated from within a registered sys container.
	if req.Container == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return nil, errors.New("Container not found")
	}

	stat := &syscall.Stat_t{
		Uid: req.Container.UID(),
		Gid: req.Container.GID(),
	}

	return stat, nil
}

func (h *NeighDefaultHandler) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	logrus.Debugf("Executing %v Open() method", h.Name)

	return nil
}

func (h *NeighDefaultHandler) Close(node domain.IOnodeIface) error {

	logrus.Debugf("Executing Close() method on %v handler", h.Name)

	return nil
}

func (h *NeighDefaultHandler) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing %v Read() method", h.Name)

	return 0, nil
}

func (h *NeighDefaultHandler) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Write() method on %v handler", h.Name)

	return 0, nil
}

func (h *NeighDefaultHandler) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	logrus.Debugf("Executing ReadDirAll() method for Req ID=%#x on %v handler; path = %s", req.ID, h.Name, n.Path())

	// Return the list of emulated resources in this directory; we don't show
	// non-emulated resources since write access to them would not be
	// permissible.

	osEmulatedFileEntries, err := emulatedFilesInfo(h.Service, n, req)
	if err != nil {
		return nil, err
	}

	var osFileEntries = make([]os.FileInfo, 0)
	for _, v := range osEmulatedFileEntries {
		osFileEntries = append(osFileEntries, v)
	}

	return osFileEntries, nil
}

func (h *NeighDefaultHandler) GetName() string {
	return h.Name
}

func (h *NeighDefaultHandler) GetPath() string {
	return h.Path
}

func (h *NeighDefaultHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *NeighDefaultHandler) GetType() domain.HandlerType {
	return h.Type
}

func (h *NeighDefaultHandler) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *NeighDefaultHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *NeighDefaultHandler) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
