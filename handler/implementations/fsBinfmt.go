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
	"os"
	"syscall"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
)

//
// /proc/sys Handler
//
type FsBinfmtHandler struct {
	Name      string
	Path      string
	Type      domain.HandlerType
	Enabled   bool
	Cacheable bool
	Service   domain.HandlerServiceIface
}

func (h *FsBinfmtHandler) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method on %v handler", h.Name)

	return n.Stat()
}

func (h *FsBinfmtHandler) Getattr(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (*syscall.Stat_t, error) {

	logrus.Debugf("Executing Getattr() method for Req ID=%#x on %v handler", req.ID, h.Name)

	commonHandler, ok := h.Service.FindHandler("commonHandler")
	if !ok {
		return nil, fmt.Errorf("No commonHandler found")
	}

	return commonHandler.Getattr(n, req)
}

func (h *FsBinfmtHandler) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	logrus.Debugf("Executing %v Open() method", h.Name)

	return nil
}

func (h *FsBinfmtHandler) Close(node domain.IOnodeIface) error {

	logrus.Debugf("Executing Close() method on %v handler", h.Name)

	return nil
}

func (h *FsBinfmtHandler) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing %v Read() method", h.Name)

	return 0, nil
}

func (h *FsBinfmtHandler) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Write() method on %v handler", h.Name)

	return 0, nil
}

func (h *FsBinfmtHandler) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	logrus.Debugf("Executing ReadDirAll() method for Req ID=%#x on %v handler", req.ID, h.Name)

	commonHandler, ok := h.Service.FindHandler("commonHandler")
	if !ok {
		return nil, fmt.Errorf("No commonHandler found")
	}

	return commonHandler.ReadDirAll(n, req)
}

func (h *FsBinfmtHandler) GetName() string {
	return h.Name
}

func (h *FsBinfmtHandler) GetPath() string {
	return h.Path
}

func (h *FsBinfmtHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *FsBinfmtHandler) GetType() domain.HandlerType {
	return h.Type
}

func (h *FsBinfmtHandler) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *FsBinfmtHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *FsBinfmtHandler) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
