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

// Method returns the sysboxfs mount-type associated to the passed (u)mount
// target. This function is deliberately overloaded to reduce to the minimum
// the number of iterations over "/proc/pid/mountinfo" file, which are
// considerable at container creation time. Function serves two main purposes:
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

	// Create a mountInfoParser struct to hold a memory-copy of the content of
	// "/proc/pid/mountinfo" file.
	mountInfoCtx, err := newMountInfoParser(pid, target)
	if err != nil {
		return INVALID_MOUNT, err
	}
	// Passed target has no associated mountpoint present in /proc/pid/mountinfo.
	// That is, we are dealing with a new-mount or a first-order bind mount
	// operation, which sysbox-fs doesn't care about.
	if mountInfoCtx == nil || mountInfoCtx.targetInfo == nil {
		return IRRELEVANT_MOUNT, nil
	}

	// Obtain the mount-flags the target is mounted with and store it in the
	// corresponding mount/umount object.
	if flags != nil {
		*flags = h.stringToFlags(mountInfoCtx.targetInfo.Opts)
	}

	// Obtain mountInfo attributes for the matching target and return right
	// away if its associated mountpoint corresponds to a procfs or a sysfs mount
	// instruction (e.g. mount -t proc proc /root/proc).
	targetInfo := mountInfoCtx.getTargetInfo()
	if targetInfo == nil {
		return IRRELEVANT_MOUNT, nil
	}
	if targetInfo.Fstype == "proc" {
		return PROCFS_MOUNT, nil
	} else if targetInfo.Fstype == "sysfs" {
		return SYSFS_MOUNT, nil
	}

	// Find the procfs or sysfs entry backing this target. If none is found,
	// then we are dealing with a mountpoint outside the procfs/sysfs subtrees.
	targetParentInfo := mountInfoCtx.getTargetParentInfo()
	if targetParentInfo == nil ||
		(targetParentInfo.Fstype != "proc" && targetParentInfo.Fstype != "sysfs") {
		return IRRELEVANT_MOUNT, nil
	}

	// Check if the target hangs from a backing procfs/sysfs that has been
	// constructed as part of a systemd-triggered mount rbind operation. Notice
	// that systemd makes use of this specific path ("unit-root") for this
	// operation, so no other path will be allowed to benefit from this
	// exception.
	targetGrandParentInfo := mountInfoCtx.getTargetGrandParentInfo()
	if targetGrandParentInfo == nil {
		return IRRELEVANT_MOUNT, nil
	}
	if (targetGrandParentInfo.Root != "/" || targetGrandParentInfo.Mountpoint != "/") &&
		strings.HasPrefix(targetInfo.Mountpoint, "/run/systemd/unit-root") {
		return IRRELEVANT_MOUNT, nil
	}

	// Adjust the mount target to accommodate general procfs/sysfs mountpoints.
	// e.g. "/root/proc"
	fsRoot := filepath.Dir(targetParentInfo.Mountpoint)
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

// Exists reports whether the named file or directory exists.
func fileExists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}
