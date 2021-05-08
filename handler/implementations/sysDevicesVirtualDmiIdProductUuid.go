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
	"sync"
	"syscall"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
)

type SysDevicesVirtualDmiIdProductUuid struct {
	domain.HandlerBase
}

var SysDevicesVirtualDmiIdProductUuid_Handler = &SysDevicesVirtualDmiIdProductUuid{
	domain.HandlerBase{
		Name:      "SysDevicesVirtualDmiIdProductUuid",
		Path:      "/sys/devices/virtual/dmi/id/product_uuid",
		Type:      domain.NODE_SUBSTITUTION | domain.NODE_BINDMOUNT | domain.NODE_PROPAGATE,
		Enabled:   true,
		Cacheable: true,
	},
}

func (h *SysDevicesVirtualDmiIdProductUuid) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method for Req ID=%#x on %v handler",
		req.ID, h.Name)

	return n.Stat()
}

func (h *SysDevicesVirtualDmiIdProductUuid) Getattr(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (*syscall.Stat_t, error) {

	logrus.Debugf("Executing GetAttr() method for Req ID=%#x on %v handler",
		req.ID, h.Name)

	return nil, nil
}

func (h *SysDevicesVirtualDmiIdProductUuid) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	logrus.Debugf("Executing Open() method for Req ID=%#x on %v handler",
		req.ID, h.Name)

	flags := n.OpenFlags()
	if flags != syscall.O_RDONLY {
		return fuse.IOerror{Code: syscall.EACCES}
	}

	return nil
}

func (h *SysDevicesVirtualDmiIdProductUuid) Close(n domain.IOnodeIface) error {

	logrus.Debugf("Executing Close() method on %v handler", h.Name)

	return nil
}

func (h *SysDevicesVirtualDmiIdProductUuid) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Read() method for Req ID=%#x on %v handler",
		req.ID, h.Name)

	// We are dealing with a single boolean element being read, so we can save
	// some cycles by returning right away if offset is any higher than zero.
	if req.Offset > 0 {
		return 0, io.EOF
	}

	cntr := req.Container

	// Ensure operation is generated from within a registered sys container.
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return 0, errors.New("Container not found")
	}

	return readFileString(h, n, req)
}

func (h *SysDevicesVirtualDmiIdProductUuid) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Write() method for Req ID=%#x on %v handler",
		req.ID, h.Name)

	return 0, nil
}

func (h *SysDevicesVirtualDmiIdProductUuid) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	return nil, nil
}

func (h *SysDevicesVirtualDmiIdProductUuid) GetName() string {
	return h.Name
}

func (h *SysDevicesVirtualDmiIdProductUuid) GetPath() string {
	return h.Path
}

func (h *SysDevicesVirtualDmiIdProductUuid) GetEnabled() bool {
	return h.Enabled
}

func (h *SysDevicesVirtualDmiIdProductUuid) GetType() domain.HandlerType {
	return h.Type
}

func (h *SysDevicesVirtualDmiIdProductUuid) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *SysDevicesVirtualDmiIdProductUuid) GetMutex() sync.Mutex {
	return h.Mutex
}

func (h *SysDevicesVirtualDmiIdProductUuid) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *SysDevicesVirtualDmiIdProductUuid) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
