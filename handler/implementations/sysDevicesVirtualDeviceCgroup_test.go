//
// Copyright 2019-2023 Nestybox, Inc.
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

package implementations_test

import (
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
	"github.com/nestybox/sysbox-fs/handler/implementations"
	"github.com/nestybox/sysbox-fs/mocks"
)

// recordingPassthrough records which passthrough operations sysDevicesVirtual
// dispatches. Operations that are not overridden panic, as they would be
// unexpected.
type recordingPassthrough struct {
	domain.PassthroughHandlerIface
	calls []string
}

func (p *recordingPassthrough) Read(n domain.IOnodeIface, req *domain.HandlerRequest) (int, error) {
	p.calls = append(p.calls, "Read")
	return 1, nil
}

func (p *recordingPassthrough) ReadInRequesterCgroup(n domain.IOnodeIface, req *domain.HandlerRequest) (int, error) {
	p.calls = append(p.calls, "ReadInRequesterCgroup")
	return 2, nil
}

func (p *recordingPassthrough) Lookup(n domain.IOnodeIface, req *domain.HandlerRequest) (os.FileInfo, error) {
	p.calls = append(p.calls, "Lookup")
	return nil, nil
}

func (p *recordingPassthrough) Write(n domain.IOnodeIface, req *domain.HandlerRequest) (int, error) {
	p.calls = append(p.calls, "Write")
	return 3, nil
}

func (p *recordingPassthrough) ReadDirAll(n domain.IOnodeIface, req *domain.HandlerRequest) ([]os.FileInfo, error) {
	p.calls = append(p.calls, "ReadDirAll")
	return nil, nil
}

func (p *recordingPassthrough) ReadLink(n domain.IOnodeIface, req *domain.HandlerRequest) (string, error) {
	p.calls = append(p.calls, "ReadLink")
	return "", nil
}

func TestSysDevicesVirtual_PassthroughRouting(t *testing.T) {

	const (
		kfdNode   = "/sys/devices/virtual/kfd/kfd/topology/nodes/1/properties"
		kfdRoot   = "/sys/devices/virtual/kfd"
		kfdPrefix = "/sys/devices/virtual/kfdx/properties" // not under kfd/
		netNode   = "/sys/devices/virtual/net/eth0/mtu"
		blockNode = "/sys/devices/virtual/block/loop0/size"
	)

	type op func(h *implementations.SysDevicesVirtual, n domain.IOnodeIface, req *domain.HandlerRequest) error

	ops := map[string]op{
		"Read": func(h *implementations.SysDevicesVirtual, n domain.IOnodeIface, req *domain.HandlerRequest) error {
			_, err := h.Read(n, req)
			return err
		},
		"Write": func(h *implementations.SysDevicesVirtual, n domain.IOnodeIface, req *domain.HandlerRequest) error {
			_, err := h.Write(n, req)
			return err
		},
		"Lookup": func(h *implementations.SysDevicesVirtual, n domain.IOnodeIface, req *domain.HandlerRequest) error {
			_, err := h.Lookup(n, req)
			return err
		},
		"ReadDirAll": func(h *implementations.SysDevicesVirtual, n domain.IOnodeIface, req *domain.HandlerRequest) error {
			_, err := h.ReadDirAll(n, req)
			return err
		},
		"ReadLink": func(h *implementations.SysDevicesVirtual, n domain.IOnodeIface, req *domain.HandlerRequest) error {
			_, err := h.ReadLink(n, req)
			return err
		},
	}

	tests := []struct {
		name      string
		path      string
		operation string
		// Passthrough calls expected. Lookup/ReadDirAll/ReadLink on kfd and
		// anything under non-passthrough nodes stay at host level (no calls),
		// and kfd writes stay dropped.
		want []string
	}{
		{"kfd node read joins requester cgroup", kfdNode, "Read", []string{"ReadInRequesterCgroup"}},
		{"kfd root read joins requester cgroup", kfdRoot, "Read", []string{"ReadInRequesterCgroup"}},
		{"kfd lookup stays at host level", kfdNode, "Lookup", nil},
		{"kfd readdir stays at host level", kfdRoot, "ReadDirAll", nil},
		{"kfd readlink stays at host level", kfdNode, "ReadLink", nil},
		{"kfd write stays dropped", kfdNode, "Write", nil},
		{"lookalike kfdx is not kfd", kfdPrefix, "Read", nil},
		{"net read uses plain passthrough", netNode, "Read", []string{"Read"}},
		{"net lookup uses passthrough", netNode, "Lookup", []string{"Lookup"}},
		{"net write uses passthrough", netNode, "Write", []string{"Write"}},
		{"other nodes read empty, no passthrough", blockNode, "Read", nil},
		{"other nodes lookup at host level", blockNode, "Lookup", nil},
	}

	h := implementations.SysDevicesVirtual_Handler
	prevSvc := h.GetService()
	defer h.SetService(prevSvc)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pt := &recordingPassthrough{}

			hs := &mocks.HandlerServiceIface{}
			hs.On("GetPassThroughHandler").Return(pt)
			h.SetService(hs)

			n := ios.NewIOnode(filepath.Base(tt.path), tt.path, 0)
			req := &domain.HandlerRequest{ID: 1, Pid: 4242, Uid: 1000, Gid: 1000, Data: make([]byte, 4096)}

			// Errors from host-level fallbacks (e.g., Lstat on a missing path)
			// are irrelevant here; only the routing decision is asserted.
			_ = ops[tt.operation](h, n, req)

			if !reflect.DeepEqual(pt.calls, tt.want) {
				t.Errorf("%s %s: passthrough calls = %v, want %v", tt.operation, tt.path, pt.calls, tt.want)
			}
		})
	}
}

func TestSysDevicesVirtual_KfdReadRequestIsForwarded(t *testing.T) {

	h := implementations.SysDevicesVirtual_Handler
	prevSvc := h.GetService()
	defer h.SetService(prevSvc)

	pt := &recordingPassthrough{}
	hs := &mocks.HandlerServiceIface{}
	hs.On("GetPassThroughHandler").Return(pt)
	h.SetService(hs)

	path := "/sys/devices/virtual/kfd/kfd/topology/nodes/0/gpu_id"
	n := ios.NewIOnode("gpu_id", path, 0)
	req := &domain.HandlerRequest{ID: 7, Pid: 4242, Uid: 1000, Gid: 1000, Data: make([]byte, 4096)}

	sz, err := h.Read(n, req)
	if err != nil {
		t.Fatalf("Read() unexpected error: %v", err)
	}

	// The requester's identity must reach the passthrough handler unchanged;
	// the device cgroup is derived from req.Pid.
	if sz != 2 {
		t.Errorf("Read() = %d, want the ReadInRequesterCgroup result (2)", sz)
	}
	if !reflect.DeepEqual(pt.calls, []string{"ReadInRequesterCgroup"}) {
		t.Errorf("passthrough calls = %v", pt.calls)
	}
}

// Reads under kfd are refused with EPERM unless the path is clean and inside
// the node: the agent reads n.Path() verbatim, while routing matches the
// cleaned relative path.
func TestSysDevicesVirtual_KfdRefusesUncleanPath(t *testing.T) {

	h := implementations.SysDevicesVirtual_Handler
	prevSvc := h.GetService()
	defer h.SetService(prevSvc)

	paths := []string{
		"/sys/devices/virtual/kfd/../kfd/kfd/topology/nodes/1/properties",
		"/sys/devices/virtual/kfd/kfd/../kfd/topology/nodes/1/properties",
		"/sys/devices/virtual/kfd/",
		"/sys/devices/virtual/kfd//kfd/topology/nodes/1/properties",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			pt := &recordingPassthrough{}
			hs := &mocks.HandlerServiceIface{}
			hs.On("GetPassThroughHandler").Return(pt)
			h.SetService(hs)

			n := ios.NewIOnode(filepath.Base(path), path, 0)
			req := &domain.HandlerRequest{ID: 9, Pid: 4242, Uid: 1000, Gid: 1000, Data: make([]byte, 4096)}

			_, err := h.Read(n, req)
			ioerr, ok := err.(fuse.IOerror)
			if !ok || ioerr.Code != syscall.EPERM {
				t.Errorf("Read(%s) error = %v, want EPERM", path, err)
			}
			if len(pt.calls) != 0 {
				t.Errorf("Read(%s) reached the passthrough handler: %v", path, pt.calls)
			}
		})
	}
}
