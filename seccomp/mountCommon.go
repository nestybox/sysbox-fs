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
// These flags are associated to operations that modify existing "/proc" or
// "/sys" mount-points, which corresponds to actions that the kernel (and not
// sysboxfs) should execute.
const sysboxProcSkipMountFlags = unix.MS_REMOUNT | unix.MS_BIND | unix.MS_MOVE

type sysboxMountType uint8

// Sysboxfs mount-types classification. Note that to prevent users from being
// able to unmount their envinroment's procfs (i.e "/proc"), we add an artificial
// type to differentiate between general procfs mounts (e.g. / "/root/proc") and
// the real procfs ("/proc").
const (
	INVALID_MOUNT     sysboxMountType = iota
	PROCFS_MOUNT                      // general procfs mount (e.g. "/root/proc")
	SYSFS_MOUNT                       // general sysfs mount (e.g. "/sys")
	REAL_PROCFS_MOUNT                 // real procfs mount (i.e. "/proc")
	BIND_MOUNT                        // procfs or sysfs bind-mount
	SPEC_MOUNT                        // cntr-specific rdonly or masked path
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

// Method determines if the passed mount target corresponds to a node sysbox-fs
// has any vested interest on.
func (m *mountHelper) isSysboxfsMount(
	pid uint32, cntr domain.ContainerIface, target string, flags *uint64) bool {

	nodeType, err := m.sysboxfsMountType(pid, cntr, target, flags)
	if err != nil {
		return false
	}

	switch nodeType {
	case PROCFS_MOUNT:
		return true
	case SYSFS_MOUNT:
		return true
	case REAL_PROCFS_MOUNT:
		return true
	case BIND_MOUNT:
		return true
	case SPEC_MOUNT:
		return true
	}

	return false
}

// Method returns the sysboxfs mount-type associated to the passed mount-target.
// This function is deliberately overloaded to reduce to the minimum the number
// of iterations over "/proc/pid/mountinfo" file, which are considerable at
// container creation time. Function serves two main purposes:
//
// * Classifies the passed mountpoints as per sysbox-fs internal mount-types.
// * Extracts the mount-flags associated to the mount-target should this one
//   is found to be already mounted.
func (h *mountHelper) sysboxfsMountType(
	pid uint32,
	cntr domain.ContainerIface,
	target string,
	flags *uint64) (sysboxMountType, error) {

	// Return right away if dealing with a real procfs.
	if target == "/proc" {
		return REAL_PROCFS_MOUNT, nil
	}

	// Obtain the mountinfo attributes corresponding to the file-systems sysbox
	// is emulating (procfs / sysfs), as well as those associated to the target
	// mountpoint.
	fsAttrs, targetAttrs, err := h.getMountinfoAttrs(pid, target)
	if err != nil {
		return INVALID_MOUNT, err
	}
	if fsAttrs == nil || targetAttrs == nil {
		return IRRELEVANT_MOUNT, nil
	}

	// Obtain the mount-flags the target is mounted with.
	if flags != nil {
		*flags = h.stringToFlags(targetAttrs.Opts)
	}

	// If dealing with a procfs or sysfs mount instruction, return here with the
	// proper mount-type.
	if !(fsAttrs.Fstype == "proc" || fsAttrs.Fstype == "sysfs") {
		return IRRELEVANT_MOUNT, nil
	} else if fsAttrs.Mountpoint == target {
		if fsAttrs.Fstype == "proc" {
			return PROCFS_MOUNT, nil
		} else if fsAttrs.Fstype == "sysfs" {
			return SYSFS_MOUNT, nil
		}
	}

	// Adjust the mount target to accommodate general procfs/sysfs mountpoints.
	// e.g. "/root/proc".
	fsRoot := filepath.Dir(fsAttrs.Mountpoint)
	if fsRoot != "/" {
		target = strings.TrimPrefix(target, fsRoot)
	}

	if cntr.IsSpecPath(target) {
		return SPEC_MOUNT, nil
	}

	if h.isBindMount(target) {
		return BIND_MOUNT, nil
	}

	return IRRELEVANT_MOUNT, nil
}

//
// Method identifies the mountinfo entry of the mount-target, as well as the
// entry of its associated 'backed' procfs / sysfs node. Function returns
// two pointers corresponding to these two elements.
//
// The following steps are executed to complete this task:
//
// 1) Collect entire list of mountpoints from "/proc/pid/mountinfo".
// 2) Iterate through this list till a full-match is found (e.g. "/root/proc/sys").
// 3) If not full-match entry is found return nil pointers -- typical case for
//    new mounts.
// 4) If the full-match node corresponds to a procfs or sysfs fstype, then
//    return its entry in both return parameters.
// 5) Otherwise, we backward-interate the list of mountpoints from the spot
//    where the match was found.
// 6) Our goal at this point is to identify if the original mountpoint target
//    (i.e. "/root/proc/sys"), 'hangs' directly (or indirectly) from a procfs (or
//	  sysfs) node.
// 7) If a backing procfs/sysfs entry is found then we return the proper entries.
// 8) Otherwise we return 'nil' in the first parameter to indicate that no backed
//    procfs/sysfs has been found.
//
func (m *mountHelper) getMountinfoAttrs(
	pid uint32, mountpoint string) (*libcontainer.Info, *libcontainer.Info, error) {

	var (
		i     int
		found bool
	)

	entries, err := libcontainer.GetMountsPid(pid)
	if err != nil {
		return nil, nil, err
	}

	// Search the table for the given mountpoint.
	for i = 0; i < len(entries); i++ {
		if entries[i].Mountpoint == mountpoint {
			if entries[i].Fstype == "proc" || entries[i].Fstype == "sysfs" {
				return entries[i], entries[i], nil
			}

			found = true
			break
		}
	}

	// Inexistent mount-target -- new mount.
	if !found {
		return nil, nil, nil
	}

	// Iterate backwards starting at 'i' till we reach an entry with 'proc'
	// fstype.
	for j := i; j > 0; j-- {
		if entries[j].Mountpoint != mountpoint &&
			!strings.HasPrefix(mountpoint, entries[j].Mountpoint) {
			continue
		}

		if entries[j].Fstype == "proc" || entries[j].Fstype == "sysfs" {
			return entries[j], entries[i], nil
		} else {
			mountpoint = filepath.Dir(mountpoint)
		}
	}

	return nil, entries[i], nil
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
