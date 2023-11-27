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
	"testing"
	"time"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/handler/implementations"
)

func TestSysDevicesVirtualDmiId_CreateCntrUuid(t *testing.T) {
	type fields struct {
		HandlerBase domain.HandlerBase
	}
	var f1 = fields{
		domain.HandlerBase{
			Name:    "SysDevicesVirtualDmiId",
			Path:    "/sys/devices/virtual/dmi/id",
			Service: hds,
		},
	}

	type args struct {
		cntr domain.ContainerIface
	}

	var a1 = args{
		cntr: css.ContainerCreate(
			"012345678901",
			uint32(1001),
			time.Time{},
			231072,
			65535,
			231072,
			65535,
			nil,
			nil,
			nil,
		),
	}

	var a2 = args{
		cntr: css.ContainerCreate(
			"0123",
			uint32(1001),
			time.Time{},
			231072,
			65535,
			231072,
			65535,
			nil,
			nil,
			nil,
		),
	}

	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		prepare func()
	}{
		{
			// Test-case 1: Proper product_uuid and and full cntr-id length.
			name:   "1",
			fields: f1,
			args:   a1,
			want:   "abcdefgh-ijkl-mnop-qrst-012345678901",
			prepare: func() {
				hds.On("HostUuid").Return("abcdefgh-ijkl-mnop-qrst-uvwxyz123456")
			},
		},
		{
			// Test-case 2: Proper product_uuid and partial cntr-id length.
			name:   "2",
			fields: f1,
			args:   a2,
			want:   "abcdefgh-ijkl-mnop-qrst-012300000000",
			prepare: func() {
				hds.On("HostUuid").Return("abcdefgh-ijkl-mnop-qrst-uvwxyz123456")
			},
		},
		{
			// Test-case 3: Missing product_uuid and full cntr-id length.
			name:   "3",
			fields: f1,
			args:   a1,
			want:   "00000000-0000-0000-0000-012345678901",
			prepare: func() {
				hds.On("HostUuid").Return("00000000-0000-0000-0000-000000000000")
			},
		},
	}

	//
	// Testcase executions.
	//
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &implementations.SysDevicesVirtualDmiId{
				HandlerBase: tt.fields.HandlerBase,
			}

			// Prepare the mocks.
			if tt.prepare != nil {
				tt.prepare()
			}

			if got := h.CreateCntrUuid(tt.args.cntr); got != tt.want {
				t.Errorf("SysDevicesVirtualDmiId_createCntrUuid() = %v, want %v", got, tt.want)
			}

			// Ensure that mocks were properly invoked and reset expectedCalls
			// object.
			hds.ExpectedCalls = nil
		})
	}
}
