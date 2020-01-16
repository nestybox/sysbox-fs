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
	invalidMount sysboxMountType = iota
	bindMount
	specMount
	procfsMount
	sysfsMount
	irrelevantMount
)

type mountInfo struct {
	hm         map[string]struct{}
	procMounts []string
	sysMounts  []string
	flagsMap   map[string]uint64
}

func newMountInfo(hdb map[string]domain.HandlerIface) *mountInfo {

	info := &mountInfo{
		hm: make(map[string]struct{}),
	}

	for _, h := range hdb {
		nodeType := h.GetType()
		nodePath := h.GetPath()

		if nodeType&(domain.NODE_BINDMOUNT|domain.NODE_PROPAGATE) ==
			(domain.NODE_BINDMOUNT | domain.NODE_PROPAGATE) {

			info.hm[nodePath] = struct{}{}

			if strings.HasPrefix(nodePath, "/proc") {
				info.procMounts = append(info.procMounts, nodePath)

			} else if strings.HasPrefix(nodePath, "/sys") {
				info.sysMounts = append(info.sysMounts, nodePath)
			}
		}
	}

	sort.Sort(sort.StringSlice(info.procMounts))
	sort.Sort(sort.StringSlice(info.sysMounts))

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

func (bm *mountInfo) isBindMount(s string) bool {

	_, ok := bm.hm[s]
	if !ok {
		return false
	}

	return true
}

func (m *mountInfo) stringToFlags(s string) uint64 {

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
			logrus.Errorf("Unsupported flagoption %s", v)
			continue
		}

		flags |= val
	}

	return flags
}

func getMountInfoType(pid uint32, mountpoint string) sysboxMountType {

	var (
		i     int
		found bool
	)

	entries, err := libcontainer.GetMountsForPid(pid)
	if err != nil {
		logrus.Error("Are we returning here? -10")
		return invalidMount
	}

	// Search the table for the given mountpoint.
	for i = 0; i < len(entries); i++ {
		if entries[i].Mountpoint == mountpoint {
			if entries[i].Fstype == "proc" {
				return procfsMount
			} else if entries[i].Fstype == "sysfs" {
				return sysfsMount
			}

			found = true
			break
		}
	}

	if !found {
		logrus.Error("Are we returning here? -11")
		return invalidMount
	}

	// Iterate backwards starting at 'i' till we reach an entry with 'proc'
	// fstype.
	for j := i; j > 0; j-- {
		if entries[j].Mountpoint != mountpoint &&
			!strings.HasPrefix(mountpoint, entries[j].Mountpoint) {
			continue
		}

		if entries[j].Fstype == "proc" || entries[j].Fstype == "sysfs" {
			logrus.Error("Are we returning here? 1")
			return bindMount
		} else {
			logrus.Error("Are we returning here? 2")
			mountpoint = filepath.Dir(mountpoint)
		}
	}

	logrus.Error("Are we returning here? 3")
	return irrelevantMount
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
