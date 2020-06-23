//
// Copyright: (C) 2020 Nestybox Inc.  All rights reserved.
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
	"bytes"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"

	"github.com/nestybox/sysbox-fs/domain"
)

//
// mountInfo reveals information about a particular mounted filesystem. This
// struct is populated from the content in the /proc/<pid>/mountinfo file. The
// fields described in each entry of /proc/self/mountinfo are described here:
// http://man7.org/linux/man-pages/man5/proc.5.html
//
// Note: Defnition borrowed from OCI runc's mount package ...
//
//   36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
//   (1)(2)(3)   (4)   (5)      (6)      (7)   (8) (9)   (10)         (11)
//
//    (1) mount ID:  unique identifier of the mount (may be reused after umount)
//    (2) parent ID:  ID of parent (or of self for the top of the mount tree)
//    (3) major:minor:  value of st_dev for files on filesystem
//    (4) root:  root of the mount within the filesystem
//    (5) mount point:  mount point relative to the process's root
//    (6) mount options:  per mount options
//    (7) optional fields:  zero or more fields of the form "tag[:value]"
//    (8) separator:  marks the end of the optional fields
//    (9) filesystem type:  name of filesystem of the form "type[.subtype]"
//    (10) mount source:  filesystem specific information or "none"
//    (11) super options:  per super block options*/
//
type mountInfo struct {
	MountID        int               // mount identifier
	ParentID       int               // parent-mount identifier
	MajorMinorVer  string            // 'st_dev' value for files in FS
	FsType         string            // file-system type
	Source         string            // file-system specific information or "none"
	Root           string            // pathname of root of the mount within the FS
	MountPoint     string            // pathname of the mount point relative to the root
	Options        map[string]string // mount-specific options
	OptionalFields map[string]string // optional-fields
	VfsOptions     map[string]string // superblock options
}

// mountInfoParser holds info about a process' mountpoints, and can be queried
// to check if a given mountpoint is a sysbox-fs managed mountpoint (i.e., base
// mount or submount).
type mountInfoParser struct {
	mh     *mountHelper
	cntr   domain.ContainerIface
	pid    uint32
	deep   bool                  // superficial vs deep parsing mode
	mpInfo map[string]*mountInfo // mountinfo, indexed by path
	idInfo map[int]*mountInfo    // mountinfo, indexed by mount ID
}

// NewMountInfoParser returns a new mountInfoParser object.
func NewMountInfoParser(
	mh *mountHelper,
	cntr domain.ContainerIface,
	pid uint32,
	deep bool) (*mountInfoParser, error) {

	mi := &mountInfoParser{
		mh:     mh,
		cntr:   cntr,
		pid:    pid,
		deep:   deep,
		mpInfo: make(map[string]*mountInfo),
		idInfo: make(map[int]*mountInfo),
	}

	err := mi.parse()
	if err != nil {
		return nil, fmt.Errorf("mountInfoParser error for pid = %d: %s", pid, err)
	}

	return mi, nil
}

// Simple wrapper over parseData() method. We are keeping this one separated
// to decouple file-handling operations and allow actual parser to take []byte
// input parameter for benchmarking purposes.
func (mi *mountInfoParser) parse() error {

	data, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/mountinfo", mi.pid))
	if err != nil {
		return err
	}

	if err := mi.parseData(data); err != nil {
		return err
	}

	return nil
}

// parseData parses the process' mountinfo file and extracts the info for the
// base mount and it's submounts.
func (mi *mountInfoParser) parseData(data []byte) error {

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {

		data := scanner.Text()
		parsedMounts, err := mi.parseComponents(data)
		if err != nil {
			return err
		}

		mi.mpInfo[parsedMounts.MountPoint] = parsedMounts
		mi.idInfo[parsedMounts.MountID] = parsedMounts
	}

	return scanner.Err()
}

// parseComponents parses a mountinfo file line.
func (mi *mountInfoParser) parseComponents(data string) (*mountInfo, error) {

	var err error

	componentSplit := strings.Split(data, " ")
	componentSplitLength := len(componentSplit)

	if componentSplitLength < 10 {
		return nil, fmt.Errorf("Not enough fields in mount string: %s", data)
	}

	// Hyphen separator is expected, otherwise line is malformed.
	if componentSplit[componentSplitLength-4] != "-" {
		return nil, fmt.Errorf("No separator found in field: %s",
			componentSplit[componentSplitLength-4])
	}

	mount := &mountInfo{
		MajorMinorVer: componentSplit[2],
		Root:          componentSplit[3],
		MountPoint:    componentSplit[4],
		FsType:        componentSplit[componentSplitLength-3],
		Source:        componentSplit[componentSplitLength-2],
	}

	mount.MountID, err = strconv.Atoi(componentSplit[0])
	if err != nil {
		return nil, fmt.Errorf("Error parsing mountID field")
	}
	mount.ParentID, err = strconv.Atoi(componentSplit[1])
	if err != nil {
		return nil, fmt.Errorf("Error parsing parentID field")
	}

	// Continue parsing process if 'deep' mode has been requested.
	if mi.deep {
		mount.Options =
			mi.parseOptionsComponent(componentSplit[5])
		mount.VfsOptions =
			mi.parseOptionsComponent(componentSplit[componentSplitLength-1])

		if componentSplit[6] != "" {
			mount.OptionalFields =
				mi.parseOptFieldsComponent(componentSplit[6 : componentSplitLength-4])
			if err != nil {
				return nil, err
			}
		}
	}

	return mount, nil
}

// parseOptionsComponent parses both regular mount-options and superblock
// mount-options.
func (mi *mountInfoParser) parseOptionsComponent(s string) map[string]string {

	optionsMap := make(map[string]string)

	// Separate all mount options.
	options := strings.Split(s, ",")
	for _, opt := range options {

		// Discern between binomial and monomial options.
		optionSplit := strings.Split(opt, "=")

		if len(optionSplit) >= 2 {
			// Example: "... size=4058184k,mode=755"
			key, value := optionSplit[0], optionSplit[1]
			optionsMap[key] = value

		} else {
			// Example: "... rw,net_cls,net_prio"
			key := optionSplit[0]
			optionsMap[key] = ""
		}
	}

	return optionsMap
}

// parseOptFieldsComponent parses the list of optional-fields.
func (mi *mountInfoParser) parseOptFieldsComponent(s []string) map[string]string {

	optionalFieldsMap := make(map[string]string)

	for _, field := range s {
		var value string

		// Separate all optional-fields.
		optionSplit := strings.SplitN(field, ":", 2)

		// Example: "... master:2 ...""
		if len(optionSplit) == 2 {
			value = optionSplit[1]
		} else {
			value = ""
		}

		// Ensure that only supported options are handled.
		switch optionSplit[0] {
		case
			"shared",
			"master",
			"propagate_from",
			"unbindable":
			optionalFieldsMap[optionSplit[0]] = value
		}
	}

	return optionalFieldsMap
}

// getParentMount returns the parent of a given mountpoint (or nil if none is
// found).
func (mi *mountInfoParser) getParentMount(info *mountInfo) *mountInfo {
	return mi.idInfo[info.ParentID]
}

// isSysboxfsBasemount checks if the given mountpoint is a sysbox-fs managed
// base mount (e.g., a procfs or sysfs mountpoint).
func (mi *mountInfoParser) isSysboxfsBaseMount(info *mountInfo) bool {
	return (info.FsType == "proc" || info.FsType == "sysfs") && info.Root == "/"
}

// isSysboxfsSubmountOf checks is the given mountpoint is a sysbox-fs managed
// submount of the given sysbox-fs base mount (e.g., /proc/sys is a sysbox-fs
// managed submount of /proc).
func (mi *mountInfoParser) isSysboxfsSubMountOf(info, baseInfo *mountInfo) bool {
	if info.ParentID != baseInfo.MountID {
		return false
	}

	// Note: submounts may contain mounts *not* managed by sysbox-fs (e.g., if a
	// user mounts something under /proc/*). Check if the given submount is
	// managed by sysbox-fs or not.

	relMountpoint := strings.TrimPrefix(info.MountPoint, baseInfo.MountPoint)

	switch baseInfo.FsType {
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

// isMountpointUnder returns true if the given mountpoint is under of one the
// mountpoints in the given set.
func isMountpointUnder(mountpoint string, mpSet []string) bool {
	for _, mp := range mpSet {
		if strings.HasSuffix(mp, mountpoint) {
			return true
		}
	}
	return false
}

// isSysboxfsSubMount returns true if the given mountpoint is a sysboxfs-managed
// submount (e.g., /proc/sys is a sysbox-fs managed submount of /proc).
func (mi *mountInfoParser) isSysboxfsSubMount(info *mountInfo) bool {

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
func (mi *mountInfoParser) GetInfo(mountpoint string) *mountInfo {
	info, found := mi.mpInfo[mountpoint]
	if !found {
		return nil
	}
	return info
}

// IsSysboxfsBaseMount checks if the given mountpoint is a sysbox-fs managed
// base mount (e.g., a procfs or sysfs mountpoint).
func (mi *mountInfoParser) IsSysboxfsBaseMount(mountpoint string) bool {

	info, found := mi.mpInfo[mountpoint]
	if !found {
		return false
	}

	return mi.isSysboxfsBaseMount(info)
}

// IsSysboxfsSubmount checks if the given mountpoint is a sysbox-fs managed
// submount (e.g., /proc/sys is a sysbox-fs managed submount of /proc).
func (mi *mountInfoParser) IsSysboxfsSubmount(mountpoint string) bool {

	info, found := mi.mpInfo[mountpoint]
	if !found {
		return false
	}

	return mi.isSysboxfsSubMount(info)
}

// IsSysboxfsRoSubmount checks if the given moutpoint is a sysbox-fs managed
// submount that is mounted as read-only.
func (mi *mountInfoParser) IsSysboxfsRoSubmount(mountpoint string) bool {

	info, found := mi.mpInfo[mountpoint]
	if !found {
		return false
	}

	if !mi.isSysboxfsSubMount(info) {
		return false
	}

	baseInfo := mi.getParentMount(info)

	// "/some/path/proc/uptime" -> "/uptime"
	relMp := strings.TrimPrefix(mountpoint, baseInfo.MountPoint)

	if baseInfo.FsType == "proc" {
		if isMountpointUnder(relMp, mi.cntr.ProcRoPaths()) {
			return true
		}
	}

	return false
}

// IsSysboxfsMaskedSubmount checks if the given moutpoint is a sysbox-fs managed
// submount that is masked (i.e., bind mounted from /dev/null).
func (mi *mountInfoParser) IsSysboxfsMaskedSubmount(mountpoint string) bool {

	info, found := mi.mpInfo[mountpoint]
	if !found {
		return false
	}

	if !mi.isSysboxfsSubMount(info) {
		return false
	}

	baseInfo := mi.getParentMount(info)

	// "/some/path/proc/uptime" -> "/uptime"
	relMp := strings.TrimPrefix(mountpoint, baseInfo.MountPoint)

	if baseInfo.FsType == "proc" {
		if isMountpointUnder(relMp, mi.cntr.ProcMaskPaths()) {
			return true
		}
	}

	return false
}

// GetSysboxfsSubMounts returns a list of sysbox-fs managed submounts under the
// given base mount (e.g., if basemount is /proc, returns all /proc/* submounts
// managed by sysbox-fs).
func (mi *mountInfoParser) GetSysboxfsSubMounts(basemount string) []string {

	baseInfo := mi.mpInfo[basemount]

	submounts := []string{}
	for mp, info := range mi.mpInfo {
		if mi.isSysboxfsSubMountOf(info, baseInfo) {
			submounts = append(submounts, mp)
		}
	}

	return submounts
}

// HasNonSysboxfsSubmount checks if there is at least one non sysbox-fs managed
// submount under the given base mount (e.g., if basemount is /proc, returns
// true if there is a mount under /proc that was not setup by sysbox-fs, such as
// when a user inside the sys container creates a mount under /proc).
func (mi *mountInfoParser) HasNonSysboxfsSubmount(basemount string) bool {

	baseInfo := mi.mpInfo[basemount]
	baseID := baseInfo.MountID

	for _, info := range mi.mpInfo {
		if info.ParentID == baseID {
			if !mi.isSysboxfsSubMountOf(info, baseInfo) {
				return true
			}
		}
	}

	return false
}
