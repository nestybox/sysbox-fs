//
// Copyright 2023 Nestybox, Inc.
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

import (
	"golang.org/x/sys/unix"
)

func processPayloadMounts(mountSysfs, mountProcfs bool) error {
	var flags uintptr = unix.MS_NOSUID | unix.MS_NOEXEC | unix.MS_NODEV | unix.MS_RELATIME

	if mountSysfs {
		if err := unix.Mount("sysfs", "/sys", "sysfs", flags, ""); err != nil {
			return err
		}
	}
	if mountProcfs {
		if err := unix.Mount("proc", "/proc", "proc", flags, ""); err != nil {
			return err
		}
	}
	return nil
}
