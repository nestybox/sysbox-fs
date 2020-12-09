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
// This handler's sole purpose is to prevent users in the host file-system from
// being able to list the file contents present in sysbox-fs mountpoint. With
// the exception of lookup(), all operations in this handler will return nil.
// Notice that only users in the host FS can invoke this handler as sysbox-fs
// is mounted in /proc and /proc/sys within the sysbox containers.
//

//
// / Handler
//
type RootHandler struct {
	domain.HandlerBase
}

func (h *RootHandler) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method on %v handler", h.Name)

	return n.Stat()
}

func (h *RootHandler) Getattr(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (*syscall.Stat_t, error) {

	logrus.Debugf("Executing Getattr() method on %v handler", h.Name)

	return nil, nil
}

func (h *RootHandler) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	logrus.Debugf("Executing %v Open() method", h.Name)

	return nil
}

func (h *RootHandler) Close(node domain.IOnodeIface) error {

	logrus.Debugf("Executing Close() method on %v handler", h.Name)

	return nil
}

func (h *RootHandler) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing %v Read() method", h.Name)

	return 0, nil
}

func (h *RootHandler) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing %v Write() method", h.Name)

	return 0, nil
}

func (h *RootHandler) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	logrus.Debugf("Executing %v ReadDirAll() method", h.Name)

	return nil, nil
}

func (h *RootHandler) GetName() string {
	return h.Name
}

func (h *RootHandler) GetPath() string {
	return h.Path
}

func (h *RootHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *RootHandler) GetType() domain.HandlerType {
	return h.Type
}

func (h *RootHandler) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *RootHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *RootHandler) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
