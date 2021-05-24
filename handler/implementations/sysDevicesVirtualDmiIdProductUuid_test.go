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

package implementations_test

import (
	"testing"
	"time"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/handler/implementations"
)

func TestSysDevicesVirtualDmiIdProductUuid_generateProductUuid(t *testing.T) {
	type fields struct {
		HandlerBase domain.HandlerBase
	}
	var f1 = fields{
		domain.HandlerBase{
			Name:      "SysDevicesVirtualDmiIdProductUuid",
			Path:      "/sys/devices/virtual/dmi/id/product_uuid",
			Type:      domain.NODE_SUBSTITUTION | domain.NODE_BINDMOUNT | domain.NODE_PROPAGATE,
			Enabled:   true,
			Cacheable: true,
		},
	}

	var c1 = css.ContainerCreate(
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
	)

	var c2 = css.ContainerCreate(
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
	)

	type args struct {
		hostUuid string
		cntr     domain.ContainerIface
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   string
	}{
		// Expected product_uuid and contr-id lengths.
		{"1", f1, args{"abcdefgh-ijkl-mnop-qrst-uvwxyz123456", c1}, "abcdefgh-ijkl-mnop-qrst-012345678901"},

		// Shorter than expected cntr-id. Padding expected.
		{"2", f1, args{"abcdefgh-ijkl-mnop-qrst-uvwxyz123456", c2}, "abcdefgh-ijkl-mnop-qrst-012300000000"},

		// Shorter than expected product_uuid. Padding expected.
		{"3", f1, args{"abcdefgh-bogus-", c1}, "abcdefgh-bogus-000000000012345678901"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &implementations.SysDevicesVirtualDmiIdProductUuid{
				HandlerBase: tt.fields.HandlerBase,
			}
			if got := h.GenerateProductUuid(tt.args.hostUuid, tt.args.cntr); got != tt.want {
				t.Errorf("SysDevicesVirtualDmiIdProductUuid.generateProductUuid() = %v, want %v", got, tt.want)
			}
		})
	}
}
