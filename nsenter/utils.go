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
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

type payloadMountsInfo struct {
	sysfsMountpoint  string
	procfsMountpoint string
	cleanup          func()
}

// This function runs when the sysbox-fs nsenter helper process requests to
// mount procfs or sysfs.
//
// Note that the container process should do so from an unshared mount
// namespace, such that the mounts are NOT visible inside the container
// (otherwise container processes will see the nsenter process mounts which are
// inherited from sysbox-fs mounts, thus leaking host info into the container).
//
// Note also that the nsenter process mounts the real procfs and sysfs, not the
// sysbox-fs emulated ones. That's because the nsenter process is not under
// seccomp-notify intercepts on mount syscalls as the container processes are.
func processPayloadMounts(mountSysfs, mountProcfs bool) (*payloadMountsInfo, error) {
	var (
		flags            uintptr
		sysfsMountpoint  string
		procfsMountpoint string
		err              error
	)

	flags = unix.MS_NOSUID | unix.MS_NOEXEC | unix.MS_NODEV | unix.MS_RELATIME

	// Ideally we want to mount procfs on /proc and sysfs on /sys, inside the
	// container; and since the mounts are done by the nsenter process in a
	// dedicated mount-ns, the container processes won't see them. While it's
	// possible for the nsenter process to mount procfs on top of the container's
	// /proc, turns out it's not possible to mount sysfs on top of the
	// container's /sys (the kernel returns a "resource busy" error). Thus, we
	// mount sysfs on a temporary ephemeral dir inside the container, at
	// /.sysbox-sysfs-<random-id>. Note that only the nsenter process can see the
	// mount (because it operates in a dedicated mount-ns). The container
	// processes will never see the mount, and therefore the
	// /.sysbox-sysfs-<random-id> dir will always look empty to container
	// processes.

	if mountSysfs {
		sysfsMountpoint, err = os.MkdirTemp("/", ".sysbox-sysfs-")
		if err != nil {
			return nil, err
		}
		if err = unix.Mount("sysfs", sysfsMountpoint, "sysfs", flags, ""); err != nil {
			os.RemoveAll(sysfsMountpoint)
			return nil, err
		}
	}
	cleanupSysfs := func() {
		if sysfsMountpoint != "" {
			unix.Unmount(sysfsMountpoint, unix.MNT_FORCE)
			os.RemoveAll(sysfsMountpoint)
		}
	}

	if mountProcfs {
		procfsMountpoint = "/proc"
		if err = unix.Mount("proc", procfsMountpoint, "proc", flags, ""); err != nil {
			cleanupSysfs()
			return nil, err
		}
	}
	cleanupProcfs := func() {
		if procfsMountpoint != "" {
			unix.Unmount(procfsMountpoint, unix.MNT_FORCE)
		}
	}

	cleanup := func() {
		cleanupSysfs()
		cleanupProcfs()
	}

	pmi := &payloadMountsInfo{
		sysfsMountpoint:  sysfsMountpoint,
		procfsMountpoint: procfsMountpoint,
		cleanup:          cleanup,
	}

	return pmi, nil
}

func replaceProcfsAndSysfsPaths(path string, pmi *payloadMountsInfo) string {

	if strings.HasPrefix(path, "/sys/") {
		path = strings.Replace(path, "/sys/", pmi.sysfsMountpoint+"/", 1)
	} else if strings.HasPrefix(path, "/proc/") {
		path = strings.Replace(path, "/proc/", pmi.procfsMountpoint+"/", 1)
	}

	return path
}
