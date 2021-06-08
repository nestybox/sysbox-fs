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
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
)

//

const (
	minProtectedSymlinksVal = 0
	maxProtectedSymlinksVal = 1
)

const (
	minProtectedHardlinksVal = 0
	maxProtectedHardlinksVal = 1
)

type ProcSysFs struct {
	domain.HandlerBase
}

var ProcSysFs_Handler = &ProcSysFs{
	domain.HandlerBase{
		Name: "ProcSysFs",
		Path: "/proc/sys/fs",
		EmuResourceMap: map[string]domain.EmuResource{
			"file-max":            {Kind: domain.FileEmuResource, Mode: os.FileMode(uint32(0644))},
			"nr-open":             {Kind: domain.FileEmuResource, Mode: os.FileMode(uint32(0644))},
			"protected_hardlinks": {Kind: domain.FileEmuResource, Mode: os.FileMode(uint32(0600))},
			"protected_symlinks":  {Kind: domain.FileEmuResource, Mode: os.FileMode(uint32(0600))},
		},
		Type:      domain.NODE_SUBSTITUTION,
		Enabled:   true,
		Cacheable: true,
	},
}

func (h *ProcSysFs) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method for Req ID=%#x on %v handler",
		req.ID, h.Name)

	// If looked-up element hasn't been found by now, let's look into the actual
	// sys container rootfs.
	procSysCommonHandler, ok := h.Service.FindHandler("/proc/sys/")
	if !ok {
		return nil, fmt.Errorf("No /proc/sys/ handler found")
	}

	return procSysCommonHandler.Lookup(n, req)
}

func (h *ProcSysFs) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	logrus.Debugf("Executing Open() method for Req ID=%#x on %v handler",
		req.ID, h.Name)

	name := n.Name()
	cntr := req.Container

	// Ensure operation is generated from within a registered sys container.
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return errors.New("Container not found")
	}

	switch name {
	case "file-max":
		return nil

	case "nr-open":
		return nil

	case "protected_hardlinks":
		return nil

	case "protected_symlinks":
		return nil
	}

	procSysCommonHandler, ok := h.Service.FindHandler("/proc/sys/")
	if !ok {
		return fmt.Errorf("No /proc/sys/ handler found")
	}

	return procSysCommonHandler.Open(n, req)
}

func (h *ProcSysFs) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing $v Read() method for Req ID=%#x on %v handler",
		req.ID, h.Name)

	// We are dealing with a single boolean element being read, so we can save
	// some cycles by returning right away if offset is any higher than zero.
	if req.Offset > 0 {
		return 0, io.EOF
	}

	name := n.Name()
	cntr := req.Container

	// Ensure operation is generated from within a registered sys container.
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return 0, errors.New("Container not found")
	}

	switch name {
	case "file-max":
		return readFileInt(h, n, req)

	case "nr-open":
		return readFileInt(h, n, req)

	case "protected_hardlinks":
		return readFileInt(h, n, req)

	case "protected_symlinks":
		return readFileInt(h, n, req)
	}

	// Refer to generic handler if no node match is found above.
	procSysCommonHandler, ok := h.Service.FindHandler("/proc/sys/")
	if !ok {
		return 0, fmt.Errorf("No /proc/sys/ handler found")
	}

	return procSysCommonHandler.Read(n, req)
}

func (h *ProcSysFs) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing %v Write() method", h.Name)

	name := n.Name()
	cntr := req.Container

	// Ensure operation is generated from within a registered sys container.
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return 0, errors.New("Container not found")
	}

	switch name {
	case "file-max":
		return writeFileMaxInt(h, n, req, false)

	case "nr-open":
		return writeFileMaxInt(h, n, req, false)

	case "protected_hardlinks":
		return writeFileInt(h, n, req, minProtectedHardlinksVal, maxProtectedHardlinksVal, false)

	case "protected_symlinks":
		return writeFileInt(h, n, req, minProtectedSymlinksVal, maxProtectedSymlinksVal, false)
	}

	// Refer to generic handler if no node match is found above.
	procSysCommonHandler, ok := h.Service.FindHandler("/proc/sys/")
	if !ok {
		return 0, fmt.Errorf("No /proc/sys/ handler found")
	}

	return procSysCommonHandler.Write(n, req)
}

func (h *ProcSysFs) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	logrus.Debugf("Executing ReadDirAll() method for Req ID=%#x on %v handler",
		req.ID, h.Name)

	// Ensure operation is generated from within a registered sys container.
	if req.Container == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return nil, errors.New("Container not found")
	}

	var fileEntries []os.FileInfo

	procSysCommonHandler, ok := h.Service.FindHandler("/proc/sys/")
	if !ok {
		return nil, fmt.Errorf("No /proc/sys/ handler found")
	}
	commonNeigh, err := procSysCommonHandler.ReadDirAll(n, req)
	if err == nil {
		for _, entry := range commonNeigh {
			fileEntries = append(fileEntries, entry)
		}
	}

	return fileEntries, nil
}

func (h *ProcSysFs) GetName() string {
	return h.Name
}

func (h *ProcSysFs) GetPath() string {
	return h.Path
}

func (h *ProcSysFs) GetEnabled() bool {
	return h.Enabled
}

func (h *ProcSysFs) GetType() domain.HandlerType {
	return h.Type
}

func (h *ProcSysFs) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *ProcSysFs) GetResourceMap() map[string]domain.EmuResource {
	return h.EmuResourceMap
}

func (h *ProcSysFs) GetResourceMutex(s string) *sync.Mutex {
	resource, ok := h.EmuResourceMap[s]
	if !ok {
		return nil
	}

	return &resource.Mutex
}
func (h *ProcSysFs) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *ProcSysFs) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
