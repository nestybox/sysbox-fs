//
// Copyright 2020 Nestybox, Inc.
//

//
// This file provides info about mounts seen by a given process' and whether some of these
// are managed by sysbox-fs.
//
// For example, in the following mount tree for a given process:
//
// |-/proc                                          proc                                                           proc    ro,nosuid,nodev,noexec,relatime,hidepid=2
// | |-/proc/bus                                    proc[/bus]                                                     proc    ro,relatime,hidepid=2
// | |-/proc/fs                                     proc[/fs]                                                      proc    ro,relatime,hidepid=2
// | |-/proc/irq                                    proc[/irq]                                                     proc    ro,relatime,hidepid=2
// | |-/proc/sysrq-trigger                          proc[/sysrq-trigger]                                           proc    ro,relatime,hidepid=2
// | |-/proc/asound                                 tmpfs                                                          tmpfs   ro,relatime,uid=165536,gid=165536
// | |-/proc/acpi                                   tmpfs                                                          tmpfs   ro,relatime,uid=165536,gid=165536
// | |-/proc/kcore                                  tmpfs[/null]                                                   tmpfs   rw,nosuid,size=65536k,mode=755
// | |-/proc/keys                                   tmpfs[/null]                                                   tmpfs   rw,nosuid,size=65536k,mode=755
// | |-/proc/timer_list                             tmpfs[/null]                                                   tmpfs   rw,nosuid,size=65536k,mode=755
// | |-/proc/sched_debug                            tmpfs[/null]                                                   tmpfs   rw,nosuid,size=65536k,mode=755
// | |-/proc/scsi                                   tmpfs                                                          tmpfs   ro,relatime,uid=165536,gid=165536
// | |-/proc/swaps                                  sysboxfs[/proc/swaps]                                          fuse    rw,nosuid,nodev,relatime,user_id=0,group_id=0,default_permissions,allow_other
// | |-/proc/sys                                    sysboxfs[/proc/sys]                                            fuse    rw,nosuid,nodev,relatime,user_id=0,group_id=0,default_permissions,allow_other
// | `-/proc/uptime                                 sysboxfs[/proc/uptime]                                         fuse    rw,nosuid,nodev,relatime,user_id=0,group_id=0,default_permissions,allow_other
//
//
// "/proc" is a sysbox-fs managed base mount.
// "/proc/*" are sysbox-fs managed submounts used to expose, hide, or emulate portions of procfs.
//
// Same applies to sysfs mounts.

package seccomp

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/nestybox/sysbox-fs/domain"
	libcontainer "github.com/nestybox/sysbox-runc/libcontainer/mount"
)

const (
	// Note: defnition borrowed from OCI runc's mount package

	/* 36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
	   (1)(2)(3)   (4)   (5)      (6)      (7)   (8) (9)   (10)         (11)

	   (1) mount ID:  unique identifier of the mount (may be reused after umount)
	   (2) parent ID:  ID of parent (or of self for the top of the mount tree)
	   (3) major:minor:  value of st_dev for files on filesystem
	   (4) root:  root of the mount within the filesystem
	   (5) mount point:  mount point relative to the process's root
	   (6) mount options:  per mount options
	   (7) optional fields:  zero or more fields of the form "tag[:value]"
	   (8) separator:  marks the end of the optional fields
	   (9) filesystem type:  name of filesystem of the form "type[.subtype]"
	   (10) mount source:  filesystem specific information or "none"
	   (11) super options:  per super block options*/
	mountinfoFormat = "%d %d %d:%d %s %s %s %s"
)

// mountInfo holds info about a process' mountpoints, and can be queried to check if a
// given mountpoint is a sysbox-fs managed mountpoint (i.e., base mount or submount).
type mountInfo struct {
	mh     *mountHelper
	cntr   domain.ContainerIface
	pid    uint32
	mpInfo map[string]*libcontainer.Info // mountinfo, indexed by path
	idInfo map[int]*libcontainer.Info    // mountinfo, indexed by mount ID
}

// NewMountInfo returns a new mountInfo object.
func NewMountInfo(mh *mountHelper, cntr domain.ContainerIface, pid uint32) (*mountInfo, error) {

	mi := &mountInfo{
		mh:     mh,
		cntr:   cntr,
		pid:    pid,
		mpInfo: make(map[string]*libcontainer.Info),
		idInfo: make(map[int]*libcontainer.Info),
	}

	err := mi.parseMountInfo(pid)
	if err != nil {
		return nil, fmt.Errorf("failed to parse mountinfo for pid = %d: %s", pid, err)
	}

	return mi, nil
}

// Parses the process' mountinfo file and extracts the info for the base mount and it's
// submounts.
func (mi *mountInfo) parseMountInfo(pid uint32) error {

	f, err := os.Open(fmt.Sprintf("/proc/%d/mountinfo", pid))
	if err != nil {
		return err
	}
	defer f.Close()

	s := bufio.NewScanner(f)

	for s.Scan() {
		if err := s.Err(); err != nil {
			return err
		}

		var (
			p              = &libcontainer.Info{}
			text           = s.Text()
			optionalFields string
		)

		if _, err := fmt.Sscanf(text, mountinfoFormat, &p.ID, &p.Parent, &p.Major, &p.Minor, &p.Root, &p.Mountpoint, &p.Opts, &optionalFields); err != nil {
			return fmt.Errorf("scanning '%s' failed: %s", text, err)
		}

		// Safe as mountinfo encodes mountpoints with spaces as \040.
		index := strings.Index(text, " - ")
		postSeparatorFields := strings.Fields(text[index+3:])
		if len(postSeparatorFields) < 3 {
			return fmt.Errorf("error found less than 3 fields post '-' in %q", text)
		}

		if optionalFields != "-" {
			p.Optional = optionalFields
		}

		p.Fstype = postSeparatorFields[0]
		p.Source = postSeparatorFields[1]
		p.VfsOpts = strings.Join(postSeparatorFields[2:], " ")

		// Store the info in the maps
		mi.mpInfo[p.Mountpoint] = p
		mi.idInfo[p.ID] = p
	}

	return nil
}

// getParentMount returns the parent of a given mountpoint (or nil if none is found)
func (mi *mountInfo) getParentMount(info *libcontainer.Info) *libcontainer.Info {
	return mi.idInfo[info.Parent]
}

// isSysboxfsBasemount checks if the given mountpoint is a sysbox-fs managed base mount
// (e.g., a procfs or sysfs mountpoint).
func (mi *mountInfo) isSysboxfsBaseMount(info *libcontainer.Info) bool {
	return (info.Fstype == "proc" || info.Fstype == "sysfs") && info.Root == "/"
}

// isSysboxfsSubmountOf checks is the given mountpoint is a sysbox-fs managed submount of
// the given sysbox-fs base mount (e.g., /proc/sys is a sysbox-fs managed submount of
// /proc).
func (mi *mountInfo) isSysboxfsSubMountOf(info, baseInfo *libcontainer.Info) bool {

	if info.Parent != baseInfo.ID {
		return false
	}

	// Note: submounts may contain mounts *not* managed by sysbox-fs (e.g., if a user
	// mounts something under /proc/*). Check if the given submount is managed by sysbox-fs
	// or not.

	relMountpoint := strings.TrimPrefix(info.Mountpoint, baseInfo.Mountpoint)

	switch baseInfo.Fstype {
	case "proc":
		if isMountpointUnder(relMountpoint, mi.mh.procMounts) ||
			isMountpointUnder(relMountpoint, mi.cntr.ProcRoPaths()) ||
			isMountpointUnder(relMountpoint, mi.cntr.ProcMaskPaths()) {
			return true
		}
	case "sysfs":
		if isMountpointUnder(relMountpoint, mi.mh.sysMounts) {
			return true
		}
	}

	return false
}

// isMountpointUnder returns true if the given mountpoint is under of one the mountpoints
// in the given set.
func isMountpointUnder(mountpoint string, mpSet []string) bool {
	for _, mp := range mpSet {
		if strings.HasSuffix(mp, mountpoint) {
			return true
		}
	}
	return false
}

// isSysboxfsSubMount returns true if the given mountpoint is a sysboxfs-managed submount
// (e.g., /proc/sys is a sysbox-fs managed submount of /proc).
func (mi *mountInfo) isSysboxfsSubMount(info *libcontainer.Info) bool {

	parentInfo := mi.getParentMount(info)

	// parent may be nil if it's a mount outside the process mount namespace
	if parentInfo == nil {
		return false
	}

	if !mi.isSysboxfsBaseMount(parentInfo) {
		return false
	}

	return mi.isSysboxfsSubMountOf(info, parentInfo)
}

// GetInfo returns the mountinfo for a given mountpoint.
func (mi *mountInfo) GetInfo(mountpoint string) *libcontainer.Info {
	info, found := mi.mpInfo[mountpoint]
	if !found {
		return nil
	}
	return info
}

// IsSysboxfsBaseMount checks if the given mountpoint is a sysbox-fs managed base mount
// (e.g., a procfs or sysfs mountpoint).
func (mi *mountInfo) IsSysboxfsBaseMount(mountpoint string) bool {

	info, found := mi.mpInfo[mountpoint]
	if !found {
		return false
	}

	return mi.isSysboxfsBaseMount(info)
}

// IsSysboxfsSubmount checks if the given moutpoint is a sysbox-fs managed submount
// (e.g., /proc/sys is a sysbox-fs managed submount of /proc).
func (mi *mountInfo) IsSysboxfsSubmount(mountpoint string) bool {

	info, found := mi.mpInfo[mountpoint]
	if !found {
		return false
	}

	return mi.isSysboxfsSubMount(info)
}

// IsSysboxfsRoSubmount checks if the given moutpoint is a sysbox-fs managed submount
// that is mounted as read-only.
func (mi *mountInfo) IsSysboxfsRoSubmount(mountpoint string) bool {

	info, found := mi.mpInfo[mountpoint]
	if !found {
		return false
	}

	if !mi.isSysboxfsSubMount(info) {
		return false
	}

	baseInfo := mi.getParentMount(info)

	// "/some/path/proc/uptime" -> "/uptime"
	relMp := strings.TrimPrefix(mountpoint, baseInfo.Mountpoint)

	if baseInfo.Fstype == "proc" {
		if isMountpointUnder(relMp, mi.cntr.ProcRoPaths()) {
			return true
		}
	}

	return false
}

// IsSysboxfsMaskedSubmount checks if the given moutpoint is a sysbox-fs managed submount
// that is masked (i.e., bind mounted from /dev/null).
func (mi *mountInfo) IsSysboxfsMaskedSubmount(mountpoint string) bool {

	info, found := mi.mpInfo[mountpoint]
	if !found {
		return false
	}

	if !mi.isSysboxfsSubMount(info) {
		return false
	}

	baseInfo := mi.getParentMount(info)

	// "/some/path/proc/uptime" -> "/uptime"
	relMp := strings.TrimPrefix(mountpoint, baseInfo.Mountpoint)

	if baseInfo.Fstype == "proc" {
		if isMountpointUnder(relMp, mi.cntr.ProcMaskPaths()) {
			return true
		}
	}

	return false
}

// GetSysboxfsSubMounts returns a list of sysbox-fs managed submounts under the given base
// mount (e.g., if basemount is /proc, returns all /proc/* submounts managed by
// sysbox-fs).
func (mi *mountInfo) GetSysboxfsSubMounts(basemount string) []string {

	baseInfo := mi.mpInfo[basemount]

	submounts := []string{}
	for mp, info := range mi.mpInfo {
		if mi.isSysboxfsSubMountOf(info, baseInfo) {
			submounts = append(submounts, mp)
		}
	}

	return submounts
}

// HasNonSysboxfsSubmount checks if there is at least one non sysbox-fs managed submount
// under the given base mount (e.g., if basemount is /proc, returns true if there is a
// mount under /proc that was not setup by sysbox-fs, such as when a user inside the sys
// container creates a mount under /proc).
func (mi *mountInfo) HasNonSysboxfsSubmount(basemount string) bool {

	baseInfo := mi.mpInfo[basemount]
	baseID := baseInfo.ID

	for _, info := range mi.mpInfo {
		if info.Parent == baseID {
			if !mi.isSysboxfsSubMountOf(info, baseInfo) {
				return true
			}
		}
	}

	return false
}
