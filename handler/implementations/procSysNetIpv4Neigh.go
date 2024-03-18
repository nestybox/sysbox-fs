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
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
)

// /proc/sys/net/ipv4/neigh handler
//
// Emulated resources:
//
// * /proc/sys/net/ipv4/default/gc_thresh1
// * /proc/sys/net/ipv4/default/gc_thresh2
// * /proc/sys/net/ipv4/default/gc_thresh3

type ProcSysNetIpv4Neigh struct {
	domain.HandlerBase
}

var ProcSysNetIpv4Neigh_Handler = &ProcSysNetIpv4Neigh{
	domain.HandlerBase{
		Name:    "ProcSysNetIpv4Neigh",
		Path:    "/proc/sys/net/ipv4/neigh",
		Enabled: true,
		EmuResourceMap: map[string]*domain.EmuResource{
			"default": {
				Kind:    domain.DirEmuResource,
				Mode:    os.FileMode(uint32(0555)),
				Enabled: true,
			},
			"default/gc_thresh1": {
				Kind:    domain.FileEmuResource,
				Mode:    os.FileMode(uint32(0644)),
				Enabled: true,
				Size:    1024,
			},
			"default/gc_thresh2": {
				Kind:    domain.FileEmuResource,
				Mode:    os.FileMode(uint32(0644)),
				Enabled: true,
				Size:    1024,
			},
			"default/gc_thresh3": {
				Kind:    domain.FileEmuResource,
				Mode:    os.FileMode(uint32(0644)),
				Enabled: true,
				Size:    1024,
			},
		},
	},
}

func (h *ProcSysNetIpv4Neigh) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	var resource string

	// Obtain relative path to the element being looked up.
	relPath, err := filepath.Rel(h.Path, n.Path())
	if err != nil {
		return nil, err
	}

	// Adjust the looked-up element to match the emulated-nodes naming.
	relPathDir := filepath.Dir(relPath)
	if relPathDir == "." ||
		strings.HasPrefix(relPath, "default/gc_thresh") {
		resource = relPath
	}

	// Return an artificial fileInfo if looked-up element matches any of the
	// emulated components.
	if v, ok := h.EmuResourceMap[resource]; ok {
		info := &domain.FileInfo{
			Fname:    resource,
			FmodTime: time.Now(),
			Fsize:    v.Size,
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
	return h.Service.GetPassThroughHandler().Lookup(n, req)
}

func (h *ProcSysNetIpv4Neigh) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (bool, error) {

	return false, nil
}

func (h *ProcSysNetIpv4Neigh) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Read() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	// We are dealing with a single boolean element being read, so we can save
	// some cycles by returning right away if offset is any higher than zero.
	if req.Offset > 0 {
		return 0, io.EOF
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
	if h.GetService().IgnoreErrors() &&
		strings.HasPrefix(relPath, "default/gc_thresh") {
		n.SetName("lo/retrans_time")
		n.SetPath("/proc/sys/net/ipv4/neigh/lo/retrans_time")
		h.EmuResourceMap["lo/retrans_time"] =
			&domain.EmuResource{Kind: domain.FileEmuResource, Mode: os.FileMode(uint32(0644))}
	}

	return readCntrData(h, n, req)
}

func (h *ProcSysNetIpv4Neigh) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Write() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

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
	if h.GetService().IgnoreErrors() &&
		strings.HasPrefix(relPath, "default/gc_thresh") {
		n.SetName("lo/retrans_time")
		n.SetPath("/proc/sys/net/ipv4/neigh/lo/retrans_time")
		h.EmuResourceMap["lo/retrans_time"] =
			&domain.EmuResource{Kind: domain.FileEmuResource, Mode: os.FileMode(uint32(0644))}
	}

	if !checkIntRange(req.Data, 0, math.MaxInt32) {
		return 0, fuse.IOerror{Code: syscall.EINVAL}
	}

	return writeCntrData(h, n, req, nil)
}

func (h *ProcSysNetIpv4Neigh) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	logrus.Debugf("Executing ReadDirAll() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

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

	// Obtain the usual entries seen within container's namespaces and add them
	// to the emulated ones.
	usualEntries, err := h.Service.GetPassThroughHandler().ReadDirAll(n, req)
	if err == nil {
		fileEntries = append(fileEntries, usualEntries...)
	}

	fileEntries = domain.FileInfoSliceUniquify(fileEntries)

	return fileEntries, nil
}

func (h *ProcSysNetIpv4Neigh) ReadLink(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (string, error) {

	logrus.Debugf("Executing ReadLink() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	return h.Service.GetPassThroughHandler().ReadLink(n, req)
}

func (h *ProcSysNetIpv4Neigh) GetName() string {
	return h.Name
}

func (h *ProcSysNetIpv4Neigh) GetPath() string {
	return h.Path
}

func (h *ProcSysNetIpv4Neigh) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *ProcSysNetIpv4Neigh) GetEnabled() bool {
	return h.Enabled
}

func (h *ProcSysNetIpv4Neigh) SetEnabled(b bool) {
	h.Enabled = b
}

func (h *ProcSysNetIpv4Neigh) GetResourcesList() []string {

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

func (h *ProcSysNetIpv4Neigh) GetResourceMutex(n domain.IOnodeIface) *sync.Mutex {

	// Obtain the relative path to the element being acted on.
	relPath, err := filepath.Rel(h.Path, n.Path())
	if err != nil {
		return nil
	}

	// Identify the associated entry matching the passed node and, if found,
	// return its mutex.
	for k, v := range h.EmuResourceMap {
		if match, _ := filepath.Match(k, relPath); match {
			return &v.Mutex
		}
	}

	return nil
}

func (h *ProcSysNetIpv4Neigh) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
