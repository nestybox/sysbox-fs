//
// Copyright 2019-2021 Nestybox, Inc.
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
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"

	"github.com/nestybox/sysbox-runc/libcontainer/user"
)

//
// /proc/sys/net/ipv4 handler
//
// Emulated resources:
//
// * /proc/sys/net/ipv4/ping_group_range
//
type ProcSysNetIpv4 struct {
	domain.HandlerBase
}

var ProcSysNetIpv4_Handler = &ProcSysNetIpv4{
	domain.HandlerBase{
		Name:    "ProcSysNetIpv4",
		Path:    "/proc/sys/net/ipv4",
		Enabled: true,
		EmuResourceMap: map[string]*domain.EmuResource{
			"ping_group_range": {
				Kind:    domain.FileEmuResource,
				Mode:    os.FileMode(uint32(0644)),
				Enabled: true,
			},
		},
	},
}

func (h *ProcSysNetIpv4) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	var resource = n.Name()

	logrus.Debugf("Executing Lookup() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	return h.Service.GetPassThroughHandler().Lookup(n, req)
}

func (h *ProcSysNetIpv4) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	return nil
}

func (h *ProcSysNetIpv4) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	var resource = n.Name()

	logrus.Debugf("Executing Read() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	// We are dealing with a single boolean element being read, so we can save
	// some cycles by returning right away if offset is any higher than zero.
	if req.Offset > 0 {
		return 0, io.EOF
	}

	return h.Service.GetPassThroughHandler().Read(n, req)
}

func (h *ProcSysNetIpv4) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	var resource = n.Name()

	logrus.Debugf("Executing Write() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	switch resource {
	case "ping_group_range":
		return h.writePingGroupRange(n, req)
	}

	// Refer to generic handler if no node match is found above.
	return h.Service.GetPassThroughHandler().Write(n, req)
}

func (h *ProcSysNetIpv4) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	var resource = n.Name()

	logrus.Debugf("Executing ReadDirAll() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	// Return all entries as seen within container's namespaces.
	return h.Service.GetPassThroughHandler().ReadDirAll(n, req)
}

func (h *ProcSysNetIpv4) GetName() string {
	return h.Name
}

func (h *ProcSysNetIpv4) GetPath() string {
	return h.Path
}

func (h *ProcSysNetIpv4) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *ProcSysNetIpv4) GetEnabled() bool {
	return h.Enabled
}

func (h *ProcSysNetIpv4) SetEnabled(b bool) {
	h.Enabled = b
}

func (h *ProcSysNetIpv4) GetResourcesList() []string {

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
func (h *ProcSysNetIpv4) GetResourceMutex(n domain.IOnodeIface) *sync.Mutex {
	resource, ok := h.EmuResourceMap[n.Name()]
	if !ok {
		return nil
	}

	return &resource.Mutex
}

func (h *ProcSysNetIpv4) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}

func (h *ProcSysNetIpv4) writePingGroupRange(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	var name = n.Name()
	var path = n.Path()
	var	origDataLength = len(req.Data)

	fields := strings.Fields(string(req.Data))
	if len(fields) != 2 {
		return 0, fuse.IOerror{Code: syscall.EINVAL}
	}

	// Obtain mindGid / maxGid integer values.

	minGid := strings.TrimSpace(fields[0])
	intMinGid, err := strconv.Atoi(minGid)
	if err != nil {
		return 0, fuse.IOerror{Code: syscall.EINVAL}
	}

	maxGid := strings.TrimSpace(fields[1])
	intMaxGid, err := strconv.Atoi(maxGid)
	if err != nil {
		return 0, fuse.IOerror{Code: syscall.EINVAL}
	}

	// Parse gid_map to extract the gid_size within the user-ns.
	idMap, err := user.ParseIDMapFile(fmt.Sprintf("/proc/%d/gid_map", req.Pid))
	if err != nil {
		return 0, fuse.IOerror{Code: syscall.EINVAL}
	}

	// Sanity-check input values.
	if intMinGid < 0 {
		return 0, fuse.IOerror{Code: syscall.EINVAL}
	}
	if intMaxGid > math.MaxInt32 {
		return 0, fuse.IOerror{Code: syscall.EINVAL}
	}

	// Cache the new provided range. Notice that this is done before we
	// adjust the input values to account for the gid-size of the container's
	// user-namespace. Our goal here is to cache the values provided by the
	// user, even though we may end up pushing slightly different values down
	// to kernel.
	cntr := req.Container
	cntr.Lock()
	cntr.SetData(path, name, fmt.Sprintf("%s\t%s", minGid, maxGid))
	cntr.Unlock()

	// Adjust the received minGid / maxGid values if these ones happen to fall
	// beyond the user-namespace boundaries.

	var adjustmentRequired = false

	if intMinGid < (int(idMap[0].ID)) {
		intMinGid = int(idMap[0].ID)
		minGid = strconv.Itoa(intMinGid)
		adjustmentRequired = true
	}
	if intMaxGid > (int(idMap[0].Count) - 1) {
		intMaxGid = (int(idMap[0].Count) - 1)
		maxGid = strconv.Itoa(intMaxGid)
		adjustmentRequired = true
	}

	if adjustmentRequired {
		req.Data = []byte(fmt.Sprintf("%s\t%s", minGid, maxGid))
	}

	// Tag the nsenter-request operation to prevent its handler from tampering
	// with the already-formatted data, and from overwriting the already-cached
	// information.
	req.Opaque = true
	req.NoCache = true

	len, err := h.Service.GetPassThroughHandler().Write(n, req)
	if err != nil {
		return len, err
	}

	return origDataLength, nil
}
