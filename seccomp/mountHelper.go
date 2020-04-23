package seccomp

import (
	"os"
	"sort"
	"strings"

	"github.com/nestybox/sysbox-fs/domain"
	"golang.org/x/sys/unix"
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

func newMountHelper(hdb map[string]domain.HandlerIface) *mountHelper {

	info := &mountHelper{
		mapMounts: make(map[string]struct{}),
	}

	// Iterate through the handlerDB to extract the set of bindmounts that need
	// to be exported (propagated) to L2 containers or L1 chrooted envs.
	for _, h := range hdb {
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
	}

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

// isNewMount returns true if the mount flags indicate creation of a new mountpoint.
func (m *mountHelper) isNewMount(flags uint64) bool {
	return flags&unix.MS_MGC_MSK == unix.MS_MGC_VAL || flags&mountModFlags == 0
}

// isRemount returns true if the mount flags indicate a remount operation.
func (m *mountHelper) isRemount(flags uint64) bool {
	return flags&unix.MS_REMOUNT == unix.MS_REMOUNT
}

// isBind returns true if the mount flags indicate a bind-mount operation.
func (m *mountHelper) isBind(flags uint64) bool {
	return flags&unix.MS_BIND == unix.MS_BIND
}

// isMove returns true if the mount flags indicate a mount move operation.
func (m *mountHelper) isMove(flags uint64) bool {
	return flags&unix.MS_MOVE == unix.MS_MOVE
}

// isRemount returns true if the mount flags indicate a mount propagation change.
func (m *mountHelper) hasPropagationFlag(flags uint64) bool {
	return flags&mountPropFlags != 0
}

// stringToFlags converts string-based mount flags (as extracted from
// /proc/pid/mountinfo), into their corresponding numerical values.
func (m *mountHelper) stringToFlags(s string) uint64 {
	var flags uint64

	fields := strings.Split(s, ",")

	for _, v := range fields {
		// Skip read-write option as it shows up in per-mount and per-vfs options.
		if v == "rw" {
			continue
		}
		val, ok := m.flagsMap[v]
		if !ok {
			continue
		}

		flags |= val
	}

	return flags
}

// filterFsFlags takes filesystem options as extracted from /proc/pid/mountinfo, filters
// out options corresponding to mount flags, and returns options corresponding to
// filesystem-specific mount data.
func (m *mountHelper) filterFsFlags(fsOpts string) string {

	fields := strings.Split(fsOpts, ",")
	opts := []string{}

	for _, v := range fields {
		_, ok := m.flagsMap[v]
		if !ok && v != "rw" {
			opts = append(opts, v)
		}
	}

	return strings.Join(opts, ",")
}

// fileExists reports whether the named file or directory exists.
func fileExists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}
