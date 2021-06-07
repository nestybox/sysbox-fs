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
	"github.com/nestybox/sysbox-libs/formatter"
)

//
// 'product_uuid' file holds 36 characters with the following layout:
//
// $ cat /sys/class/dmi/id/product_uuid
// e617c421-0026-4941-9e95-56a1ab1f4cb3
//
// For emulation purposes we will split 'product_uuid' content in two separate
// fields. The first 24 characters will continue to match those seen by the
// hosts. The last 12 characters will be extracted from the container ID field.
// Example:
//
// e617c421-0026-4941-9e95-<sys-cntr-id-01>
// e617c421-0026-4941-9e95-<sys-cntr-id-02>
// etc.
//

const (
	hostUuidLen = 24
	cntrUuidLen = 12
)

type SysDevicesVirtualDmiId struct {
	domain.HandlerBase
}

var SysDevicesVirtualDmiId_Handler = &SysDevicesVirtualDmiId{
	domain.HandlerBase{
		Name: "SysDevicesVirtualDmiId",
		Path: "/sys/devices/virtual/dmi/id",
		EmuResourceMap: map[string]domain.EmuResource{
			"product_uuid": {
				Kind:     domain.FileEmuResource,
				Mode:     os.FileMode(uint32(0400)),
				NodeType: domain.NODE_SUBSTITUTION | domain.NODE_BINDMOUNT,
			},
		},
		Enabled:   true,
		Cacheable: true,
	},
}

func (h *SysDevicesVirtualDmiId) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method for Req ID=%#x on %v handler",
		req.ID, h.Name)

	return n.Stat()
}

func (h *SysDevicesVirtualDmiId) Getattr(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (*syscall.Stat_t, error) {

	logrus.Debugf("Executing GetAttr() method for Req ID=%#x on %v handler",
		req.ID, h.Name)

	return nil, nil
}

func (h *SysDevicesVirtualDmiId) Open(
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

func (h *SysDevicesVirtualDmiId) Close(n domain.IOnodeIface) error {

	logrus.Debugf("Executing Close() method on %v handler", h.Name)

	return nil
}

func (h *SysDevicesVirtualDmiId) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Read() method for Req ID=%#x on %v handler",
		req.ID, h.Name)

	// We are dealing with a single boolean element being read, so we can save
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

	cntr.Lock()

	// Check if this resource has been initialized for this container. Otherwise,
	// fetch the information from the host FS.
	data, ok := cntr.Data(path, name)
	if !ok {
		val, err := fetchFileData(h, n, cntr)
		if err != nil && err != io.EOF {
			cntr.Unlock()
			return 0, err
		}

		data = h.GenerateProductUuid(val, cntr)
		cntr.SetData(path, name, data)
	}

	cntr.Unlock()

	data += "\n"

	return copyResultBuffer(req.Data, []byte(data))
}

func (h *SysDevicesVirtualDmiId) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Write() method for Req ID=%#x on %v handler",
		req.ID, h.Name)

	return 0, nil
}

func (h *SysDevicesVirtualDmiId) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	return nil, nil
}

func (h *SysDevicesVirtualDmiId) GetName() string {
	return h.Name
}

func (h *SysDevicesVirtualDmiId) GetPath() string {
	return h.Path
}

func (h *SysDevicesVirtualDmiId) GetEnabled() bool {
	return h.Enabled
}

func (h *SysDevicesVirtualDmiId) GetType() domain.HandlerType {
	return h.Type
}

func (h *SysDevicesVirtualDmiId) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *SysDevicesVirtualDmiId) GetResourceMutex(s string) *sync.Mutex {
	resource, ok := h.EmuResourceMap[s]
	if !ok {
		return nil
	}

	return &resource.Mutex
}

func (h *SysDevicesVirtualDmiId) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *SysDevicesVirtualDmiId) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}

func (h *SysDevicesVirtualDmiId) GenerateProductUuid(
	hostUuid string,
	cntr domain.ContainerIface) string {

	var (
		hostUuidPref string
		cntrUuidPref string
	)

	// Pad hostUuid with zeroes if it doesn't fill its slot.
	if len(hostUuid) < hostUuidLen {
		hostUuidPref = padRight(hostUuid, "0", hostUuidLen)
	} else {
		hostUuidPref = hostUuid[:hostUuidLen]
	}

	// Pad hostUuid with zeroes if it doesn't fill its slot.
	cntrUuidPref = formatter.ContainerID{cntr.ID()}.String()
	if len(cntrUuidPref) < cntrUuidLen {
		cntrUuidPref = padRight(cntrUuidPref, "0", cntrUuidLen)
	}

	return hostUuidPref + cntrUuidPref
}
