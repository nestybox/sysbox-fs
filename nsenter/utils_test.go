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

package nsenter

import "testing"

func TestReplaceProcfsAndSysfsPaths(t *testing.T) {
	tests := []struct {
		name string
		path string
		pmi  payloadMountsInfo
		want string
	}{
		{"sysfs remounted", "/sys/devices/virtual/net/lo/mtu",
			payloadMountsInfo{sysfsMountpoint: "/tmp/sysfs123"}, "/tmp/sysfs123/devices/virtual/net/lo/mtu"},
		{"procfs remounted", "/proc/sys/kernel/pid_max",
			payloadMountsInfo{procfsMountpoint: "/tmp/procfs123"}, "/tmp/procfs123/sys/kernel/pid_max"},
		{"sysfs not remounted", "/sys/devices/virtual/kfd/kfd/topology/nodes/1/gpu_id",
			payloadMountsInfo{}, "/sys/devices/virtual/kfd/kfd/topology/nodes/1/gpu_id"},
		{"procfs not remounted", "/proc/sys/kernel/pid_max",
			payloadMountsInfo{sysfsMountpoint: "/tmp/sysfs123"}, "/proc/sys/kernel/pid_max"},
		{"other path", "/etc/hostname",
			payloadMountsInfo{sysfsMountpoint: "/tmp/sysfs123", procfsMountpoint: "/tmp/procfs123"}, "/etc/hostname"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pmi := tt.pmi
			if got := replaceProcfsAndSysfsPaths(tt.path, &pmi); got != tt.want {
				t.Errorf("replaceProcfsAndSysfsPaths(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}
