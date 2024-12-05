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
	"errors"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

type payloadMountsInfo struct {
	sysfsMountpoint  string
	procfsMountpoint string
	cleanup          func(string, string)
}

// This function runs when the sysbox-fs nsenter helper process requests to
// mount procfs or sysfs.
//
// This function assumes the nsenter agent is running in an unshared mount
// namespace, such that the procfs and sysfs mounts it creates are NOT visible
// inside the container (otherwise container processes will see the nsenter
// process mounts, which is not what we want).
//
// Note also that the nsenter process mounts the "real" procfs and sysfs, not
// the sysbox-fs emulated one we use for containers, but does so from within the
// container's namespaces (except it's own mount-ns as described above). This
// way the nsenter agent can access host info for the container that may not be
// available to the container itself. This info can then be used to emulate
// procfs and sysfs resources inside the container.
//
// [@ctalledo]: this function needs cleanup, it can accept either mountSyfs or
// mountProcfs, but not both (because for the case where the container is read-only,
// it mounts on the same dir (/dev), so there's a collision).
func processPayloadMounts(mountSysfs, mountProcfs bool) (*payloadMountsInfo, error) {
	var (
		flags            uintptr
		sysfsMountpoint  string
		procfsMountpoint string
		err              error
	)

	flags = unix.MS_NOSUID | unix.MS_NOEXEC | unix.MS_NODEV | unix.MS_RELATIME

	// Note: ideally we want to mount procfs on /proc and sysfs on /sys, inside
	// the container; and since the mounts are done by the nsenter process in a
	// dedicated mount-ns, the container processes won't see them. While it's
	// possible for the nsenter process to mount procfs on top of the container's
	// /proc, turns out it's not possible to mount sysfs on top of the
	// container's /sys (the kernel returns a "resource busy" error). Thus, we
	// mount sysfs on a temporary ephemeral dir inside the container, at
	// /.sysbox-sysfs-<random-id>. Note that while that directory is visible
	// inside the container (for a very brief period of time while the nsenter
	// agent does its thing), the container can't see the sysfs mount on that dir
	// (only the nsenter process can see the mount because it operates in a
	// dedicated mount-ns). The container processes will never see the mount, and
	// therefore the /.sysbox-sysfs-<random-id> dir will always look empty to
	// container processes.
	if mountSysfs {

		sysfsMountpoint, err = os.MkdirTemp("/", ".sysbox-sysfs-")
		if errors.Is(err, unix.EROFS) {
			// @ctalledo: hack: if the container has a read-only filesystem, then
			// we can't create the temporary sysfs mount dir on it. In this case we
			// use a directory that we know is present in the container (e.g.,
			// "/dev") to mount sysfs. Since the mount occurs in the nsenter
			// agent's own mount-ns, it's not visible to anyone else (i.e, the
			// container can still access the "/dev" dir without noticing anything
			// differently on it).
			sysfsMountpoint = "/dev"

		} else if err != nil {
			return nil, err
		}
		if err = unix.Mount("sysfs", sysfsMountpoint, "sysfs", flags, ""); err != nil {
			os.RemoveAll(sysfsMountpoint)
			return nil, err
		}
	}
	cleanupSysfs := func(mountpoint string) {
		if mountpoint != "" {
			unix.Unmount(mountpoint, unix.MNT_DETACH)
			if strings.HasPrefix(mountpoint, "/.sysbox-sysfs-") {
				os.RemoveAll(mountpoint)
			}
		}
	}

	if mountProcfs {
		procfsMountpoint, err = os.MkdirTemp("/", ".sysbox-procfs-")
		if errors.Is(err, unix.EROFS) {
			// @ctalledo: hack: if the container has a read-only filesystem, then
			// we can't create the temporary procfs mount dir on it. In this case we
			// use a directory that we know is present in the container (e.g.,
			// "/dev") to mount procfs. Since the mount occurs in the nsenter
			// agent's own mount-ns, it's not visible to anyone else (i.e, the
			// container can still access the "/dev" dir without noticing anything
			// differently on it).
			procfsMountpoint = "/dev"

		} else if err != nil {
			return nil, err
		}
		if err = unix.Mount("proc", procfsMountpoint, "proc", flags, ""); err != nil {
			cleanupSysfs(sysfsMountpoint)
			return nil, err
		}
	}
	cleanupProcfs := func(mountpoint string) {
		if mountpoint != "" {
			unix.Unmount(mountpoint, unix.MNT_DETACH)
			if strings.HasPrefix(mountpoint, "/.sysbox-procfs-") {
				os.RemoveAll(mountpoint)
			}
		}
	}

	cleanup := func(sysfsMountpoint, procfsMountpoint string) {
		cleanupSysfs(sysfsMountpoint)
		cleanupProcfs(procfsMountpoint)
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
