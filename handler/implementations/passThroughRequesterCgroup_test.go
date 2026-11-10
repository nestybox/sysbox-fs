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
	"syscall"
	"testing"

	"github.com/stretchr/testify/mock"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
	"github.com/nestybox/sysbox-fs/handler/implementations"
	"github.com/nestybox/sysbox-fs/nsenter"
)

// isRequesterCgroupRead matches the request for a read that runs in the
// requester's device cgroup: no sysfs or procfs remount, for the given file.
func isRequesterCgroupRead(path string) interface{} {
	return mock.MatchedBy(func(m *domain.NSenterMessage) bool {
		p, ok := m.Payload.(*domain.ReadFilePayload)
		return ok && m.Type == domain.ReadFileRequest &&
			p.File == path && p.Offset == 0 && !p.MountSysfs && !p.MountProcfs
	})
}

// TestPassThrough_ReadInRequesterCgroup checks the nsenter request behind a
// requester-cgroup read. The agent must join no namespace, remount nothing,
// and be asked to join the requester's device cgroup.
func TestPassThrough_ReadInRequesterCgroup(t *testing.T) {

	const (
		path    = "/sys/devices/virtual/kfd/kfd/topology/nodes/1/properties"
		content = "gfx_target_version 110501\n"
	)

	h := &implementations.PassThrough{
		domain.HandlerBase{
			Name:    "PassThrough",
			Path:    "PassThrough",
			Service: hds,
		},
	}

	n := ios.NewIOnode("properties", path, 0)
	req := &domain.HandlerRequest{
		ID:   1,
		Pid:  1001,
		Uid:  1000,
		Gid:  1000,
		Data: make([]byte, len(content)),
	}

	t.Run("no namespaces, no remount, join requester cgroup", func(t *testing.T) {
		ev := &nsenter.NSenterEvent{Pid: req.Pid}

		// uid/gid come from /proc for the requester (see process.Uid()).
		nss.On("NewEvent",
			req.Pid, mock.Anything, mock.Anything,
			&[]domain.NStype{},
			uint32(0),
			isRequesterCgroupRead(path),
			(*domain.NSenterMessage)(nil),
			false).Return(ev)
		nss.On("SendRequestEvent", ev).Return(nil)
		nss.On("ReceiveResponseEvent", ev).Return(&domain.NSenterMessage{
			Type:    domain.ReadFileResponse,
			Payload: []byte(content),
		})

		sz, err := h.ReadInRequesterCgroup(n, req)
		if err != nil {
			t.Fatalf("ReadInRequesterCgroup() error = %v", err)
		}
		if sz != len(content) {
			t.Errorf("ReadInRequesterCgroup() = %d, want %d", sz, len(content))
		}
		if !ev.JoinRequesterCgroup {
			t.Errorf("request does not ask the agent to join the requester's cgroup")
		}

		nss.AssertExpectations(t)
		nss.ExpectedCalls = nil
	})

	t.Run("kernel errno reaches the requester", func(t *testing.T) {
		ev := &nsenter.NSenterEvent{Pid: req.Pid}

		// uid/gid come from /proc for the requester (see process.Uid()).
		nss.On("NewEvent",
			req.Pid, mock.Anything, mock.Anything,
			&[]domain.NStype{},
			uint32(0),
			isRequesterCgroupRead(path),
			(*domain.NSenterMessage)(nil),
			false).Return(ev)
		nss.On("SendRequestEvent", ev).Return(nil)
		// The agent's error reaches the handler as a decoded fuse.IOerror value
		// (see nsenter/event.go, processResponse).
		nss.On("ReceiveResponseEvent", ev).Return(&domain.NSenterMessage{
			Type:    domain.ErrorResponse,
			Payload: fuse.IOerror{Code: syscall.EPERM, Message: "open: operation not permitted"},
		})

		_, err := h.ReadInRequesterCgroup(n, req)
		ioerr, ok := err.(fuse.IOerror)
		if !ok || ioerr.Code != syscall.EPERM {
			t.Errorf("ReadInRequesterCgroup() error = %v, want EPERM", err)
		}

		nss.AssertExpectations(t)
		nss.ExpectedCalls = nil
	})

	t.Run("unknown requester fails closed without an agent", func(t *testing.T) {
		// No NSenter expectations are set: any agent dispatch fails the test.
		noPid := &domain.HandlerRequest{ID: 2, Pid: 0, Data: make([]byte, 8)}

		_, err := h.ReadInRequesterCgroup(n, noPid)
		ioerr, ok := err.(fuse.IOerror)
		if !ok || ioerr.Code != syscall.EPERM {
			t.Errorf("ReadInRequesterCgroup() error = %v, want EPERM", err)
		}
	})
}
