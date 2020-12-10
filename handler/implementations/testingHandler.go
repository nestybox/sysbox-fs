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
// Testing Handler
//
type TestingHandler struct {
	domain.HandlerBase
}

func (h *TestingHandler) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method on %v handler", h.Name)

	return n.Stat()
}

func (h *TestingHandler) Getattr(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (*syscall.Stat_t, error) {

	logrus.Debugf("Executing Getattr() method on %v handler", h.Name)

	return nil, nil
}

func (h *TestingHandler) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	logrus.Debugf("Executing %v Open() method", h.Name)

	return nil
}

func (h *TestingHandler) Close(node domain.IOnodeIface) error {

	logrus.Debugf("Executing Close() method on %v handler", h.Name)

	return nil
}

func (h *TestingHandler) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing %v Read() method", h.Name)

	if req.Offset > 0 {
		return 0, io.EOF
	}

	return 0, nil
}

func (h *TestingHandler) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	return 0, nil
}

func (h *TestingHandler) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	logrus.Debugf("Executing ReadDirAll() method on %v handler", h.Name)

	procSysCommonHandler, ok := h.Service.FindHandler("procSysCommonHandler")
	if !ok {
		return nil, fmt.Errorf("No procSysCommonHandler found")
	}

	return procSysCommonHandler.ReadDirAll(n, req)
}

func (h *TestingHandler) GetName() string {
	return h.Name
}

func (h *TestingHandler) GetPath() string {
	return h.Path
}

func (h *TestingHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *TestingHandler) GetType() domain.HandlerType {
	return h.Type
}

func (h *TestingHandler) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *TestingHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *TestingHandler) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
