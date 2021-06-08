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
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
)

type ProcSysNetIpv4Neigh struct {
	domain.HandlerBase
}

var ProcSysNetIpv4Neigh_Handler = &ProcSysNetIpv4Neigh{
	domain.HandlerBase{
		Name: "ProcSysNetIpv4Neigh",
		Path: "/proc/sys/net/ipv4/neigh",
		EmuResourceMap: map[string]domain.EmuResource{
			"default":            {Kind: domain.DirEmuResource, Mode: os.FileMode(uint32(0555))},
			"default/gc_thresh1": {Kind: domain.FileEmuResource, Mode: os.FileMode(uint32(0644))},
			"default/gc_thresh2": {Kind: domain.FileEmuResource, Mode: os.FileMode(uint32(0644))},
			"default/gc_thresh3": {Kind: domain.FileEmuResource, Mode: os.FileMode(uint32(0644))},
		},
		Enabled:   true,
		Cacheable: true,
	},
}

func (h *ProcSysNetIpv4Neigh) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method on %v handler", h.Name)

	// Obtain relative path to the element being looked up.
	relPath, err := filepath.Rel(h.Path, n.Path())
	if err != nil {
		return nil, err
	}

	var lookupEntry string

	// Adjust the looked-up element to match the emulated-nodes naming.
	relPathDir := filepath.Dir(relPath)
	if relPathDir == "." ||
		strings.HasPrefix(relPath, "default/gc_thresh") {
		lookupEntry = relPath
	}

	// Return an artificial fileInfo if looked-up element matches any of the
	// emulated components.
	if v, ok := h.EmuResourceMap[lookupEntry]; ok {
		info := &domain.FileInfo{
			Fname:    lookupEntry,
			FmodTime: time.Now(),
		}

		if v.Kind == domain.DirEmuResource {
			info.Fmode = os.FileMode(uint32(os.ModeDir)) | v.Mode
			info.FisDir = true
		} else if v.Kind == domain.FileEmuResource {
			info.Fmode = v.Mode
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

func (h *ProcSysNetIpv4Neigh) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	return nil
}

func (h *ProcSysNetIpv4Neigh) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Read() method for Req ID=%#x on %v handler",
		req.ID, h.Name)

	// We are dealing with a single boolean element being read, so we can save
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

	// Obtain relative path to the element being written.
	relPath, err := filepath.Rel(h.Path, n.Path())
	if err != nil {
		return 0, err
	}

	// Skip if node is not part of the emulated components.
	if _, ok := h.EmuResourceMap[relPath]; !ok {
		return 0, nil
	}

	// As the "default" dir node isn't exposed within containers, sysbox's
	// integration testsuites will fail when executing within the test framework.
	// In these cases, we will redirect all "default" queries to a static node
	// that is always present in the testing environment.
	if strings.HasPrefix(relPath, "default/gc_thresh") &&
		h.GetService().IgnoreErrors() {
		n.SetName("lo/retrans_time")
		n.SetPath("/proc/sys/net/ipv4/neigh/lo/retrans_time")
		h.EmuResourceMap["lo/retrans_time"] =
			domain.EmuResource{Kind: domain.FileEmuResource, Mode: os.FileMode(uint32(0644))}
	}

	return readFileInt(h, n, req)
}

func (h *ProcSysNetIpv4Neigh) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing %v Write() method", h.Name)

	cntr := req.Container

	// Ensure operation is generated from within a registered sys container.
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return 0, errors.New("Container not found")
	}

	// Obtain relative path to the element being written.
	relPath, err := filepath.Rel(h.Path, n.Path())
	if err != nil {
		return 0, err
	}

	// Skip if node is not part of the emulated components.
	if _, ok := h.EmuResourceMap[relPath]; !ok {
		return 0, nil
	}

	// As the "default" dir node isn't exposed within containers, sysbox's
	// integration testsuites will fail when executing within the test framework.
	// In these cases, we will redirect all "default" queries to a static node
	// that is always present in the testing environment.
	if strings.HasPrefix(relPath, "default/gc_thresh") &&
		h.GetService().IgnoreErrors() {
		n.SetName("lo/retrans_time")
		n.SetPath("/proc/sys/net/ipv4/neigh/lo/retrans_time")
		h.EmuResourceMap["lo/retrans_time"] =
			domain.EmuResource{Kind: domain.FileEmuResource, Mode: os.FileMode(uint32(0644))}
	}

	return writeFileInt(h, n, req, 0, MaxInt, false)
}

func (h *ProcSysNetIpv4Neigh) ReadDirAll(
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

	var (
		info        *domain.FileInfo
		fileEntries []os.FileInfo
	)

	// Obtain relative path to the element being read.
	relpath, err := filepath.Rel(h.Path, n.Path())
	if err != nil {
		return nil, err
	}

	// Iterate through map of virtual components.
	for k, _ := range h.EmuResourceMap {

		if relpath == filepath.Dir(k) {
			info = &domain.FileInfo{
				Fname:    filepath.Base(k),
				Fmode:    os.ModeDir,
				FmodTime: time.Now(),
				FisDir:   true,
			}

			fileEntries = append(fileEntries, info)

		} else if relpath != "." && relpath == filepath.Dir(k) {
			info = &domain.FileInfo{
				Fname:    filepath.Base(k),
				FmodTime: time.Now(),
			}

			fileEntries = append(fileEntries, info)
		}
	}

	// Also collect procfs entries as seen within container's namespaces.
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

func (h *ProcSysNetIpv4Neigh) GetName() string {
	return h.Name
}

func (h *ProcSysNetIpv4Neigh) GetPath() string {
	return h.Path
}

func (h *ProcSysNetIpv4Neigh) GetEnabled() bool {
	return h.Enabled
}

func (h *ProcSysNetIpv4Neigh) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *ProcSysNetIpv4Neigh) GetResourceMap() map[string]domain.EmuResource {
	return h.EmuResourceMap
}

func (h *ProcSysNetIpv4Neigh) GetResourceMutex(s string) *sync.Mutex {
	resource, ok := h.EmuResourceMap[s]
	if !ok {
		return nil
	}

	return &resource.Mutex
}

func (h *ProcSysNetIpv4Neigh) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *ProcSysNetIpv4Neigh) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
