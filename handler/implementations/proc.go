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
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
)

//
// /proc handler
//

// /proc/swaps static header
var swapsHeader = "Filename                                Type            Size    Used    Priority"

type Proc struct {
	domain.HandlerBase
}

var Proc_Handler = &Proc{
	domain.HandlerBase{
		Name:    "Proc",
		Path:    "/proc",
		Enabled: true,
		EmuResourceMap: map[string]*domain.EmuResource{
			"sys": {
				Kind:    domain.DirEmuResource,
				Mode:    os.ModeDir | os.FileMode(uint32(0555)),
				Enabled: true,
			},
			"swaps": {
				Kind:    domain.FileEmuResource,
				Mode:    os.FileMode(uint32(0444)),
				Enabled: true,
			},
			"uptime": {
				Kind:    domain.FileEmuResource,
				Mode:    os.FileMode(uint32(0444)),
				Enabled: true,
			},
		},
	},
}

func (h *Proc) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	var resource = n.Name()

	logrus.Debugf("Executing Lookup() for Req ID=%#x, %v handler, resource %s",
		req.ID, h.Name, resource)

	// Return an artificial fileInfo if looked-up element matches any of the
	// emulated components.
	if v, ok := h.EmuResourceMap[resource]; ok {
		info := &domain.FileInfo{
			Fname:    resource,
			Fmode:    v.Mode,
			FmodTime: time.Now(),
		}

		if v.Kind == domain.DirEmuResource {
			info.FisDir = true
		}

		return info, nil
	}

	return n.Stat()
}

func (h *Proc) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	var resource = n.Name()

	logrus.Debugf("Executing Open() for Req ID=%#x, %v handler, resource %s",
		req.ID, h.Name, resource)

	flags := n.OpenFlags()

	switch resource {
	case "sys":
		return nil

	case "swaps", "uptime":
		if flags != syscall.O_RDONLY {
			return fuse.IOerror{Code: syscall.EACCES}
		}
	}

	return nil
}

func (h *Proc) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	var resource = n.Name()

	logrus.Debugf("Executing Read() for Req ID=%#x, %v handler, resource %s",
		req.ID, h.Name, resource)

	// We are dealing with a single boolean element being read, so we can save
	// some cycles by returning right away if offset is any higher than zero.
	if req.Offset > 0 {
		return 0, io.EOF
	}

	switch resource {
	case "swaps":
		return h.readSwaps(n, req)

	case "uptime":
		return h.readUptime(n, req)
	}

	return 0, nil
}

func (h *Proc) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	return 0, nil
}

func (h *Proc) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	var resource = n.Name()

	logrus.Debugf("Executing ReadDirAll() for Req ID=%#x, %v handler, resource %s",
		req.ID, h.Name, resource)

	switch resource {
	case "sys":
		procSysCommonHandler, ok := h.Service.FindHandler("/proc/sys/")
		if !ok {
			return nil, fmt.Errorf("No /proc/sys/ found")
		}

		return procSysCommonHandler.ReadDirAll(n, req)
	}

	return nil, nil
}

func (h *Proc) GetName() string {
	return h.Name
}

func (h *Proc) GetPath() string {
	return h.Path
}

func (h *Proc) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *Proc) GetEnabled() bool {
	return h.Enabled
}

func (h *Proc) SetEnabled(b bool) {
	h.Enabled = b
}

func (h *Proc) GetResourcesList() []string {

	var resources []string

	for resourceKey, resource := range h.EmuResourceMap {
		resource.Mutex.Lock()
		if !resource.Enabled {
			resource.Mutex.Unlock()
			continue
		}
		resource.Mutex.Unlock()

		resources = append(resources, filepath.Join(h.GetPath(), resourceKey))
	}

	return resources
}

func (h *Proc) GetResourceMutex(s string) *sync.Mutex {
	resource, ok := h.EmuResourceMap[s]
	if !ok {
		return nil
	}

	return &resource.Mutex
}

func (h *Proc) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}

func (h *Proc) readSwaps(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing %v Read() method", h.Name)

	if req.Offset > 0 {
		return 0, io.EOF
	}

	name := n.Name()
	path := n.Path()
	cntr := req.Container

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

func (h *Proc) readUptime(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing %v Read() method", h.Name)

	// We are dealing with a single integer element being read, so we can save
	// some cycles by returning right away if offset is any higher than zero.
	if req.Offset > 0 {
		return 0, io.EOF
	}

	cntr := req.Container

	// Ensure operation is generated from within a registered sys container.
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return 0, errors.New("Container not found")
	}

	//
	// We can assume that by the time a user generates a request to read
	// /proc/uptime, the embedding container has been fully initialized,
	// so cs.ctime is already holding a valid value.
	//
	data := cntr.Ctime()

	// Calculate container's uptime, convert it to float to obtain required
	// precission (as per host FS), and finally format it into string for
	// storage purposes.
	//
	// TODO: Notice that we are dumping the same values into the two columns
	// expected in /proc/uptime. The value utilized for the first column is
	// an accurate one (uptime seconds), however, the second one is just
	// an approximation.
	//
	uptimeDur := time.Now().Sub(data) / time.Nanosecond
	var uptime float64 = uptimeDur.Seconds()
	uptimeStr := fmt.Sprintf("%.2f", uptime)

	result := []byte(uptimeStr + " " + uptimeStr + "\n")

	return copyResultBuffer(req.Data, result)
}
