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

package mount

import (
	"sort"
	"strings"

	"github.com/nestybox/sysbox-fs/domain"
	"golang.org/x/sys/unix"

	iradix "github.com/hashicorp/go-immutable-radix"
)

// The mountPropFlags in a mount syscall indicate a change in the propagation type of an
// existing mountpoint.
const mountPropFlags = (unix.MS_SHARED | unix.MS_PRIVATE | unix.MS_SLAVE | unix.MS_UNBINDABLE)

// The mountModFlags in a mount syscall indicate a change to an existing mountpoint. If
// these flags are not present, the mount syscall creates a new mountpoint.
const mountModFlags = (unix.MS_REMOUNT | unix.MS_BIND | unix.MS_MOVE | mountPropFlags)

// mountHelper provides methods to aid in obtaining info about container mountpoints
// managed by sysboxfs.
type mountHelper struct {
	mapMounts  map[string]struct{} // map of all sysboxfs bind-mounts (rdonly + mask)
	procMounts []string            // slice of procfs bind-mounts
	sysMounts  []string            // slice of sysfs bind-mounts
	flagsMap   map[string]uint64   // helper map to aid in flag conversion
}

func newMountHelper(hdb *iradix.Tree) *mountHelper {

	info := &mountHelper{
		mapMounts: make(map[string]struct{}),
	}

	// Iterate through the handlerDB to extract the set of bindmounts that need
	// to be exported (propagated) to L2 containers or L1 chrooted envs.
	hdb.Root().Walk(func(key []byte, val interface{}) bool {
		h := val.(domain.HandlerIface)
		nodeType := h.GetType()
		nodePath := h.GetPath()

		if nodeType&(domain.NODE_BINDMOUNT|domain.NODE_PROPAGATE) ==
			(domain.NODE_BINDMOUNT | domain.NODE_PROPAGATE) {

			info.mapMounts[nodePath] = struct{}{}

			if strings.HasPrefix(nodePath, "/proc") {
				info.procMounts = append(info.procMounts, nodePath)

			} else if strings.HasPrefix(nodePath, "/sys") {
				info.sysMounts = append(info.sysMounts, nodePath)
			}
		}

		return false
	})

	// Both procMounts and sysMounts slices should be sorted (alphanumerically
	// in this case), for mount / umount operations to succeed.
	sort.Sort(sort.StringSlice(info.procMounts))
	sort.Sort(sort.StringSlice(info.sysMounts))

	//
	// Initialize a flagsMap to help in "/proc/pid/mountHelper" parsing. Note that
	// even though these are a subset of the flags supported by Linux kernel, these
	// are the ones that are taken into account to generate /proc/pid/mountinfo
	// content. Details here:
	// https://github.com/torvalds/linux/blob/master/fs/proc_namespace.c#L131
	// https://github.com/torvalds/linux/blob/master/include/linux/mount.h
	//
	info.flagsMap = map[string]uint64{
		"ro":          unix.MS_RDONLY,      // Read-only file-system
		"nodev":       unix.MS_NODEV,       // Will not interpret character or block special devices
		"noexec":      unix.MS_NOEXEC,      // Will not allow execution of any binaries
		"nosuid":      unix.MS_NOSUID,      // Will not allow set-user/group-identifier
		"noatime":     unix.MS_NOATIME,     // Will not update the file access-time when reading from a file
		"nodiratime":  unix.MS_NODIRATIME,  // Will not update the directory access time
		"relatime":    unix.MS_RELATIME,    // Updates inode access-times relative to modify time
		"strictatime": unix.MS_STRICTATIME, // Always update last access time
		"sync":        unix.MS_SYNCHRONOUS, // Make writes synchronous
	}

	return info
}

// ProcMounts returns sysbox-fs' procfs submounts.
func (m *mountHelper) ProcMounts() []string {
	return m.procMounts
}

// SysMounts returns sysbox-fs' sysfs submounts.
func (m *mountHelper) SysMounts() []string {
	return m.sysMounts
}

// IsNewMount returns true if the mount flags indicate creation of a new mountpoint.
func (m *mountHelper) IsNewMount(flags uint64) bool {
	return flags&unix.MS_MGC_MSK == unix.MS_MGC_VAL || flags&mountModFlags == 0
}

// IsRemount returns true if the mount flags indicate a remount operation.
func (m *mountHelper) IsRemount(flags uint64) bool {
	return flags&unix.MS_REMOUNT == unix.MS_REMOUNT
}

// IsBind returns true if the mount flags indicate a bind-mount operation.
func (m *mountHelper) IsBind(flags uint64) bool {
	return flags&unix.MS_BIND == unix.MS_BIND
}

// IsMove returns true if the mount flags indicate a mount move operation.
func (m *mountHelper) IsMove(flags uint64) bool {
	return flags&unix.MS_MOVE == unix.MS_MOVE
}

// HasPropagationFlag returns true if the mount flags indicate a mount
// propagation change.
func (m *mountHelper) HasPropagationFlag(flags uint64) bool {
	return flags&mountPropFlags != 0
}

// IsReadOnlyMount returns 'true' if the mount flags indicate a read-only mount
// operation. Otherwise, 'false' is returned to refer to a read-write instruction.
func (m *mountHelper) IsReadOnlyMount(flags uint64) bool {
	return flags&unix.MS_RDONLY == unix.MS_RDONLY
}

// StringToFlags converts string-based mount flags (as extracted from
// /proc/pid/mountinfo), into their corresponding numerical values.
func (m *mountHelper) StringToFlags(s map[string]string) uint64 {
	var flags uint64

	for k, _ := range s {
		// Skip read-write option as it shows up in per-mount and per-vfs options.
		if k == "rw" {
			continue
		}
		val, ok := m.flagsMap[k]
		if !ok {
			continue
		}

		flags |= val
	}

	return flags
}

// FilterFsFlags takes filesystem options as extracted from /proc/pid/mountinfo, filters
// out options corresponding to mount flags, and returns options corresponding to
// filesystem-specific mount data.
func (m *mountHelper) FilterFsFlags(fsOpts map[string]string) string {

	opts := []string{}

	for k, _ := range fsOpts {
		_, ok := m.flagsMap[k]
		if ok && k != "rw" {
			opts = append(opts, k)
		}
	}

	return strings.Join(opts, ",")
}
