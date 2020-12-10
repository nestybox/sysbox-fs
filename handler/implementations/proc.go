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

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/sirupsen/logrus"
)

//
// /proc handler
//
// This handler is used for accesses to non-emulated resources under
// /var/lib/sysboxfs/<container-id>/proc.
//
// Since that directory is not mounted inside a system container, such accesses
// are only possible from host level. They typically occur when sysbox-runc is
// creating the container and it bind-mounts sysbox-fs to subdirs under the
// container's "/proc" (e.g., /proc/uptime, /proc/sys, etc); as part of the
// bind-mount, the kernel walks the bind-source path, which results in sysbox-fs
// receiving lookups into /proc. Thus, this handler only serves such lookups;
// all other handler methods are purposefuly dummy, as we generally want to
// ignore accesses to sysbox-fs from host level.

type ProcHandler struct {
	domain.HandlerBase
}

func (h *ProcHandler) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method on %v handler", h.Name)

	return n.Stat()
}

func (h *ProcHandler) Getattr(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (*syscall.Stat_t, error) {

	logrus.Debugf("Executing Getattr() method on %v handler", h.Name)

	return nil, nil
}

func (h *ProcHandler) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	logrus.Debugf("Executing %v Open() method", h.Name)

	return nil
}

func (h *ProcHandler) Close(n domain.IOnodeIface) error {

	logrus.Debugf("Executing Close() method on %v handler", h.Name)

	return nil
}

func (h *ProcHandler) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing %v Read() method", h.Name)

	return 0, nil
}

func (h *ProcHandler) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing %v Write() method", h.Name)

	return 0, nil
}

func (h *ProcHandler) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	return nil, nil
}

func (h *ProcHandler) GetName() string {
	return h.Name
}

func (h *ProcHandler) GetPath() string {
	return h.Path
}

func (h *ProcHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *ProcHandler) GetType() domain.HandlerType {
	return h.Type
}

func (h *ProcHandler) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *ProcHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *ProcHandler) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
