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
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
)

//
// /proc/swaps Handler
//

type Proc struct {
	domain.HandlerBase
}

var Proc_Handler = &Proc{
	domain.HandlerBase{
		Name: "Proc",
		Path: "/proc",
		EmuResourceMap: map[string]domain.EmuResource{
			"sys": {
				Kind:     domain.FileEmuResource,
				Mode:     os.ModeDir | os.FileMode(uint32(0555)),
				NodeType: domain.NODE_SUBSTITUTION | domain.NODE_BINDMOUNT,
			},
			"swaps": {
				Kind:     domain.FileEmuResource,
				Mode:     os.FileMode(uint32(0444)),
				NodeType: domain.NODE_SUBSTITUTION | domain.NODE_BINDMOUNT,
			},
			"update": {
				Kind:     domain.FileEmuResource,
				Mode:     os.FileMode(uint32(0444)),
				NodeType: domain.NODE_SUBSTITUTION | domain.NODE_BINDMOUNT,
			},
		},
		Enabled:   true,
		Cacheable: false,
	},
}

func (h *Proc) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method on %v handler", h.Name)

	var node string

	// Return an artificial fileInfo if looked-up element matches any of the
	// emulated components.
	if v, ok := h.EmuResourceMap[node]; ok {
		info := &domain.FileInfo{
			Fname:    node,
			Fmode:    v.Mode,
			FmodTime: time.Now(),
		}

		if v.Kind == domain.DirEmuResource {
			info.FisDir = true
		}

		return info, nil
	}

	// If looked-up element hasn't been found by now, look into the actual
	// container rootfs.
	procSysCommonHandler, ok := h.Service.FindHandler("/proc/sys/")
	if !ok {
		return nil, fmt.Errorf("No /proc/sys/ handler found")
	}

	return procSysCommonHandler.Lookup(n, req)
}

func (h *Proc) Getattr(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (*syscall.Stat_t, error) {

	logrus.Debugf("Executing Getattr() method on %v handler", h.Name)

	return nil, nil
}

func (h *Proc) Open(
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

func (h *Proc) Close(n domain.IOnodeIface) error {

	logrus.Debugf("Executing Close() method on %v handler", h.Name)

	if err := n.Close(); err != nil {
		logrus.Debugf("Error closing file %v", h.Path)
		return fuse.IOerror{Code: syscall.EIO}
	}

	return nil
}

func (h *Proc) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Read() method for Req ID=%#x on %v handler",
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
	case "swaps":
		return h.readSwaps(n, req)

	case "uptime":
		return h.readUptime(n, req)
	}

	// Refer to generic handler if no node match is found above.
	procSysCommonHandler, ok := h.Service.FindHandler("/proc/sys/")
	if !ok {
		return 0, fmt.Errorf("No /proc/sys/ handler found")
	}

	return procSysCommonHandler.Read(n, req)
}

func (h *Proc) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	return 0, nil
}

func (h *Proc) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	return nil, nil
}

func (h *Proc) GetName() string {
	return h.Name
}

func (h *Proc) GetPath() string {
	return h.Path
}

func (h *Proc) GetEnabled() bool {
	return h.Enabled
}

func (h *Proc) GetType() domain.HandlerType {
	return h.Type
}

func (h *Proc) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *Proc) GetResourceMutex(s string) *sync.Mutex {
	resource, ok := h.EmuResourceMap[s]
	if !ok {
		return nil
	}

	return &resource.Mutex
}

func (h *Proc) SetEnabled(val bool) {
	h.Enabled = val
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
