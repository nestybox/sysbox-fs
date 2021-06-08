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
	"io"
	"os"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
)

type SysModuleNfconntrackParameters struct {
	domain.HandlerBase
}

var SysModuleNfconntrackParameters_Handler = &SysModuleNfconntrackParameters{
	domain.HandlerBase{
		Name: "SysModuleNfconntrackParameters",
		Path: "/sys/module/nf_conntrack/parameters",
		EmuResourceMap: map[string]domain.EmuResource{
			"hashsize": {
				Kind: domain.FileEmuResource,
				Mode: os.FileMode(uint32(0600)),
			},
		},
		Enabled:   true,
		Cacheable: true,
	},
}

func (h *SysModuleNfconntrackParameters) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method for Req ID=%#x on %v handler",
		req.ID, h.Name)

	return n.Stat()
}

func (h *SysModuleNfconntrackParameters) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	logrus.Debugf("Executing Open() method for Req ID=%#x on %v handler",
		req.ID, h.Name)

	return nil
}

func (h *SysModuleNfconntrackParameters) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Read() method for Req ID=%#x on %v handler",
		req.ID, h.Name)

	// We are dealing with a single boolean element being read, so we can save
	// some cycles by returning right away if offset is any higher than zero.
	if req.Offset > 0 {
		return 0, io.EOF
	}

	return readFileInt(h, n, req)
}

func (h *SysModuleNfconntrackParameters) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Write() method for Req ID=%#x on %v handler",
		req.ID, h.Name)

	return writeFileInt(h, n, req, 0, MaxInt, true)
}

func (h *SysModuleNfconntrackParameters) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	return nil, nil
}

func (h *SysModuleNfconntrackParameters) GetName() string {
	return h.Name
}

func (h *SysModuleNfconntrackParameters) GetPath() string {
	return h.Path
}

func (h *SysModuleNfconntrackParameters) GetEnabled() bool {
	return h.Enabled
}

func (h *SysModuleNfconntrackParameters) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *SysModuleNfconntrackParameters) GetResourceMap() map[string]domain.EmuResource {
	return h.EmuResourceMap
}

func (h *SysModuleNfconntrackParameters) GetResourceMutex(s string) *sync.Mutex {
	resource, ok := h.EmuResourceMap[s]
	if !ok {
		return nil
	}

	return &resource.Mutex
}

func (h *SysModuleNfconntrackParameters) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *SysModuleNfconntrackParameters) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
