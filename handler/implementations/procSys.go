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
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
)

//
// /proc/sys Handler
//

type ProcSys struct {
	domain.HandlerBase
}

var ProcSys_Handler = &ProcSys{
	domain.HandlerBase{
		Name:      "ProcSys",
		Path:      "/proc/sys",
		Type:      domain.NODE_SUBSTITUTION | domain.NODE_BINDMOUNT | domain.NODE_PROPAGATE,
		Enabled:   true,
		Cacheable: false,
	},
}

func (h *ProcSys) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method for Req ID=%#x on %v handler", req.ID, h.Name)

	return n.Stat()
}

func (h *ProcSys) Getattr(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (*syscall.Stat_t, error) {

	logrus.Debugf("Executing Getattr() method for Req ID=%#x on %v handler", req.ID, h.Name)

	return nil, nil
}

func (h *ProcSys) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	logrus.Debugf("Executing Open() method for Req ID=%#x on %v handler", req.ID, h.Name)

	return nil
}

func (h *ProcSys) Close(node domain.IOnodeIface) error {

	logrus.Debugf("Executing Close() method on %v handler", h.Name)

	return nil
}

func (h *ProcSys) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Read() method for Req ID=%#v method on %v handler", req.ID, h.Name)

	if req.Offset > 0 {
		return 0, io.EOF
	}

	return 0, nil
}

func (h *ProcSys) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	return 0, nil
}

func (h *ProcSys) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	logrus.Debugf("Executing ReadDirAll() method for Req ID=%#x on %v handler", req.ID, h.Name)

	procSysCommonHandler, ok := h.Service.FindHandler("/proc/sys/")
	if !ok {
		return nil, fmt.Errorf("No /proc/sys/ found")
	}

	return procSysCommonHandler.ReadDirAll(n, req)
}

func (h *ProcSys) GetName() string {
	return h.Name
}

func (h *ProcSys) GetPath() string {
	return h.Path
}

func (h *ProcSys) GetEnabled() bool {
	return h.Enabled
}

func (h *ProcSys) GetType() domain.HandlerType {
	return h.Type
}

func (h *ProcSys) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *ProcSys) GetMutex() sync.Mutex {
	return h.Mutex
}

func (h *ProcSys) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *ProcSys) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
