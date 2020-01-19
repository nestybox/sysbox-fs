package seccomp

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/nestybox/sysbox-fs/domain"
	libcontainer "github.com/nestybox/sysbox-runc/libcontainer/mount"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// Set of mount-flags to skip during procfs / sysfs mount syscall processing.
// These flags are associated to operations that modify existing mount-points,
// which corresponds to actions that the kernel (and not sysboxfs) should
// execute.
const sysboxProcSkipMountFlags = unix.MS_REMOUNT | unix.MS_BIND | unix.MS_MOVE

type sysboxMountType uint8

// Sysboxfs mount-types classification.
const (
	INVALID_MOUNT     sysboxMountType = iota
	BIND_MOUNT                        // procfs or sysfs bind-mount
	SPEC_MOUNT                        // cntr-specific rdonly or masked path
	PROCFS_MOUNT                      // proper procfs mount (e.g. "/root/proc")
	SYSFS_MOUNT                       // proper sysfs mount (e.g. "/sys")
	REAL_PROCFS_MOUNT                 // real procfs mount (i.e. "/proc")
	IRRELEVANT_MOUNT                  // valid, yet irrelevant mountpoint
)

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

	// Iterate through the handleDB to extract the set of bindmounts that need
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
		"ro":         unix.MS_RDONLY,     // Read-only file-system
		"nodev":      unix.MS_NODEV,      // Will not interpret character or block special devices
		"noexec":     unix.MS_NOEXEC,     // Will not allow execution of any binaries
		"nosuid":     unix.MS_NOSUID,     // Will not allow set-user/group-identifier
		"noatime":    unix.MS_NOATIME,    // Will not update the file access-time when reading from a file
		"nodiratime": unix.MS_NODIRATIME, // Will not update the directory access time
		"relatime":   unix.MS_RELATIME,   // Updates inode access-times relative to modify time
	}

	return info
}

// Method returns 'true' if passed string corresponds to a sysboxfs bind-mount
// node. Note that method is fully re-entrant as the map in question will not be
// modified, thus, there's no need for concurrency primitives here.
func (m *mountHelper) isBindMount(s string) bool {

	_, ok := m.mapMounts[s]
	if !ok {
		return false
	}

	return true
}

// Helper method to convert string-based mount flags (as extracted from
// /proc/pid/mountinfo), into their corresponding numerical values.
func (m *mountHelper) stringToFlags(s string) uint64 {

	var flags uint64

	fields := strings.Split(s, ",")

	for _, v := range fields {
		// Skip read-write option as technically it's not a flag by itself.
		// That is, "rw" == "!ro".
		if v == "rw" {
			continue
		}

		val, ok := m.flagsMap[v]
		if !ok {
			logrus.Errorf("Unsupported mount flag option %s", v)
			continue
		}

		flags |= val
	}

	return flags
}

// Extract the flags associated to any given mountpoint as per kernel's mountinfo
// file content.
func (m *mountHelper) getMountFlags(pid uint32, target string) (uint64, error) {

	info, err := libcontainer.GetMountAtPid(pid, target)
	if err != nil {
		return 0, err
	}

	return m.stringToFlags(info.Opts), nil
}

// Method determines if the passed mount target matches a sysbox-fs node.
func (m *mountHelper) isSysboxfsMount(
	pid uint32, cntr domain.ContainerIface, target string) bool {

	nodeType := m.sysboxfsMountType(pid, cntr, target)

	switch nodeType {
	case BIND_MOUNT:
		return true
	case SPEC_MOUNT:
		return true
	case PROCFS_MOUNT:
		return true
	case SYSFS_MOUNT:
		return true
	case REAL_PROCFS_MOUNT:
		return true
	}

	return false
}

// Method returns the sysboxfs mount type associated to the passed mountpoint
// target.
func (m *mountHelper) sysboxfsMountType(
	pid uint32, cntr domain.ContainerIface, target string) sysboxMountType {

	if cntr.IsSpecPath(target) {
		return SPEC_MOUNT
	}

	if m.isBindMount(target) {
		return BIND_MOUNT
	}

	return m.getmountHelperType(pid, target)
}

//
// Method executes the following steps to determine the sysboxfs mount-type
// associated to any given mountpoint:
//
// 1) Collect entire list of mountpoints as per /proc/pid/mountinfo.
// 2) Iterate through this list till a full-match is found (i.e. /root/proc/sys).
// 3) If not full-match node is found return an error (INVALID_MOUNT).
// 4) If the full-match node corresponds to a procfs or sysfs fstype, then
//    we return its associated type.
// 5) Otherwise, we backward-interate the list of mountpoints from the spot
//    where the match was found.
// 6) Our goal at this point is to identify if the original mountpoint target
//    (i.e. /root/proc/sys), 'hangs' directly (or indirectly) from a procfs (or
//	  sysfs) node.
// 7) If a backing procfs/sysfs entry is found then we return claiming that the
//    target is a sysboxfs bind-mount node.
// 8) Otherwise we return 'irrelevant-mount' to indicate that, even though this
//    is an existing mountpoint, it holds no value for sysboxfs mount processing
//    logic.
//
func (m *mountHelper) getmountHelperType(
	pid uint32, mountpoint string) sysboxMountType {

	var (
		i     int
		found bool
	)

	entries, err := libcontainer.GetMountsPid(pid)
	if err != nil {
		return INVALID_MOUNT
	}

	// Search the table for the given mountpoint.
	for i = 0; i < len(entries); i++ {
		if entries[i].Mountpoint == mountpoint {
			if entries[i].Fstype == "proc" {
				if mountpoint == "/proc" {
					return REAL_PROCFS_MOUNT
				}
				return PROCFS_MOUNT

			} else if entries[i].Fstype == "sysfs" {
				return SYSFS_MOUNT
			}

			found = true
			break
		}
	}

	if !found {
		return INVALID_MOUNT
	}

	// Iterate backwards starting at 'i' till we reach an entry with 'proc'
	// fstype.
	for j := i; j > 0; j-- {
		if entries[j].Mountpoint != mountpoint &&
			!strings.HasPrefix(mountpoint, entries[j].Mountpoint) {
			continue
		}

		if entries[j].Fstype == "proc" || entries[j].Fstype == "sysfs" {
			// Technically, it could have either been a bind-mount or a
			// spec-mount (rdonly or mask paths), but picking one or the
			// other doesn't change anything as treatment for both types
			// is expected to be the same in caller's logic.
			return BIND_MOUNT
		} else {
			mountpoint = filepath.Dir(mountpoint)
		}
	}

	return IRRELEVANT_MOUNT
}

// Exists reports whether the named file or directory exists.
func fileExists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}
