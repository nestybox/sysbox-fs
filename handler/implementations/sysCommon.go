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
	"os"
	"syscall"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
)

//
// Due to the fact that sysbox-fs' procfs is sourced at /proc/sys, there's no
// much this handler needs to do. This handler's purpose is to be able to manage
// operations associated to /proc bind-mounts such as cpuinfo, meminfo, etc).
//

//
// /sys commmon handler
//
type SysCommonHandler struct {
	domain.HandlerBase
}

func (h *SysCommonHandler) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method on %v handler", h.Name)

	return n.Stat()
}

func (h *SysCommonHandler) Getattr(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (*syscall.Stat_t, error) {

	logrus.Debugf("Executing Getattr() method on %v handler", h.Name)

	return nil, nil
}

func (h *SysCommonHandler) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	logrus.Debugf("Executing %v Open() method", h.Name)

	return nil
}

func (h *SysCommonHandler) Close(n domain.IOnodeIface) error {

	logrus.Debugf("Executing Close() method on %v handler", h.Name)

	return nil
}

func (h *SysCommonHandler) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing %v Read() method", h.Name)

	return 0, nil
}

func (h *SysCommonHandler) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing %v Write() method", h.Name)

	return 0, nil
}

func (h *SysCommonHandler) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	return nil, nil
}

func (h *SysCommonHandler) GetName() string {
	return h.Name
}

func (h *SysCommonHandler) GetPath() string {
	return h.Path
}

func (h *SysCommonHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *SysCommonHandler) GetType() domain.HandlerType {
	return h.Type
}

func (h *SysCommonHandler) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *SysCommonHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *SysCommonHandler) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
