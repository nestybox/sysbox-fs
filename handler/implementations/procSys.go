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
	"syscall"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
)

//
// /proc/sys Handler
//
type ProcSysHandler struct {
	Name      string
	Path      string
	Type      domain.HandlerType
	Enabled   bool
	Cacheable bool
	Service   domain.HandlerServiceIface
}

func (h *ProcSysHandler) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method for Req ID=%#x on %v handler", req.ID, h.Name)

	return n.Stat()
}

func (h *ProcSysHandler) Getattr(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (*syscall.Stat_t, error) {

	logrus.Debugf("Executing Getattr() method for Req ID=%#x on %v handler", req.ID, h.Name)

	return nil, nil
}

func (h *ProcSysHandler) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	logrus.Debugf("Executing Open() method for Req ID=%#x on %v handler", req.ID, h.Name)

	return nil
}

func (h *ProcSysHandler) Close(node domain.IOnodeIface) error {

	logrus.Debugf("Executing Close() method on %v handler", h.Name)

	return nil
}

func (h *ProcSysHandler) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Read() method for Req ID=%#v method on %v handler", req.ID, h.Name)

	if req.Offset > 0 {
		return 0, io.EOF
	}

	return 0, nil
}

func (h *ProcSysHandler) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	return 0, nil
}

func (h *ProcSysHandler) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	logrus.Debugf("Executing ReadDirAll() method for Req ID=%#x on %v handler", req.ID, h.Name)

	commonHandler, ok := h.Service.FindHandler("commonHandler")
	if !ok {
		return nil, fmt.Errorf("No commonHandler found")
	}

	return commonHandler.ReadDirAll(n, req)
}

func (h *ProcSysHandler) GetName() string {
	return h.Name
}

func (h *ProcSysHandler) GetPath() string {
	return h.Path
}

func (h *ProcSysHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *ProcSysHandler) GetType() domain.HandlerType {
	return h.Type
}

func (h *ProcSysHandler) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *ProcSysHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *ProcSysHandler) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
