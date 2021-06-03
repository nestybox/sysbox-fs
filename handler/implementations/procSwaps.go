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

//
// /proc/swaps Handler
//

type ProcSwaps struct {
	domain.HandlerBase
}

var ProcSwaps_Handler = &ProcSwaps{
	domain.HandlerBase{
		Name:      "ProcSwaps",
		Path:      "/proc/swaps",
		Type:      domain.NODE_SUBSTITUTION | domain.NODE_BINDMOUNT,
		Enabled:   true,
		Cacheable: false,
	},
}

// /proc/swaps static header
var swapsHeader = "Filename                                Type            Size    Used    Priority"

func (h *ProcSwaps) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method on %v handler", h.Name)

	return n.Stat()
}

func (h *ProcSwaps) Getattr(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (*syscall.Stat_t, error) {

	logrus.Debugf("Executing Getattr() method on %v handler", h.Name)

	return nil, nil
}

func (h *ProcSwaps) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	logrus.Debugf("Executing %v Open() method", h.Name)

	flags := n.OpenFlags()
	if flags != syscall.O_RDONLY {
		return fuse.IOerror{Code: syscall.EACCES}
	}

	if err := n.Open(); err != nil {
		logrus.Debugf("Error opening file %v", h.Path)
		return fuse.IOerror{Code: syscall.EIO}
	}

	return nil
}

func (h *ProcSwaps) Close(n domain.IOnodeIface) error {

	logrus.Debugf("Executing Close() method on %v handler", h.Name)

	if err := n.Close(); err != nil {
		logrus.Debugf("Error closing file %v", h.Path)
		return fuse.IOerror{Code: syscall.EIO}
	}

	return nil
}

func (h *ProcSwaps) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing %v Read() method", h.Name)

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

	// If no modification has been ever made to this container's swapping mode,
	// then let's assume that swapping in OFF by default.
	data, ok := cntr.Data(path, name)
	if !ok || data == "swapoff" {
		result := []byte(swapsHeader + "\n")
		return copyResultBuffer(req.Data, result)
	}

	var result []byte

	// If swapping is enabled ("swapon" value was explicitly set), extract the
	// information directly from the host fs. Note that this action displays
	// stats of the overall system, and not of the container itself, but it's
	// a valid approximation for now given that kernel doesn't expose anything
	// close to this.
	_, err := n.Read(result)
	if err != nil && err != io.EOF {
		return 0, err
	}

	return copyResultBuffer(req.Data, result)
}

func (h *ProcSwaps) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	return 0, nil
}

func (h *ProcSwaps) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	return nil, nil
}

func (h *ProcSwaps) GetName() string {
	return h.Name
}

func (h *ProcSwaps) GetPath() string {
	return h.Path
}

func (h *ProcSwaps) GetEnabled() bool {
	return h.Enabled
}

func (h *ProcSwaps) GetType() domain.HandlerType {
	return h.Type
}

func (h *ProcSwaps) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *ProcSwaps) GetMutex() sync.Mutex {
	return h.Mutex
}

func (h *ProcSwaps) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *ProcSwaps) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
