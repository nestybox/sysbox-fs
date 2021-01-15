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

package mount

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"

	"github.com/nestybox/sysbox-fs/domain"
	"golang.org/x/sys/unix"
)

// mountInfoParser holds info about a process' mountpoints, and can be queried
// to check if a given mountpoint is a sysbox-fs managed mountpoint (i.e., base
// mount or submount).
type mountInfoParser struct {
	mh        *mountHelper
	cntr      domain.ContainerIface
	pid       uint32
	deep      bool                           // superficial vs deep parsing mode
	mpInfo    map[string]*domain.MountInfo   // mountinfo, indexed by path
	idInfo    map[int]*domain.MountInfo      // mountinfo, indexed by mount ID
	devIdInfo map[string][]*domain.MountInfo // mountinfo, indexed by mount major/minor ver
	service   *MountService                  // backpointer to mount service
}

// newMountInfoParser returns a new mountInfoParser object.
func newMountInfoParser(
	cntr domain.ContainerIface,
	pid uint32,
	deep bool,
	mts *MountService) (*mountInfoParser, error) {

	mip := &mountInfoParser{
		cntr:      cntr,
		pid:       pid,
		deep:      deep,
		mpInfo:    make(map[string]*domain.MountInfo),
		idInfo:    make(map[int]*domain.MountInfo),
		devIdInfo: make(map[string][]*domain.MountInfo),
		service:   mts,
	}

	err := mip.parse()
	if err != nil {
		return nil, fmt.Errorf("mountInfoParser error for pid = %d: %s", pid, err)
	}

	return mip, nil
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

		// Optimization needed here -- this logic makes sense only for remount ops.
		devIdSlice, ok := mi.devIdInfo[parsedMounts.MajorMinorVer]
		if ok {
			mi.devIdInfo[parsedMounts.MajorMinorVer] =
				append(devIdSlice, parsedMounts)
		} else {
			mi.devIdInfo[parsedMounts.MajorMinorVer] =
				[]*domain.MountInfo{parsedMounts}
		}
	}

	return scanner.Err()
}

// parseComponents parses a mountinfo file line.
func (mi *mountInfoParser) parseComponents(data string) (*domain.MountInfo, error) {

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

	mount := &domain.MountInfo{
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

func (mi *mountInfoParser) extractMountInfo() ([]byte, error) {

	if mi.process.Root() == "/" {
		data, err :=
			ioutil.ReadFile(fmt.Sprintf("/proc/%d/mountinfo", mi.process.Pid()))
		if err != nil {
			return nil, err
		}
		return data, nil
	}

	// In chroot-jail setups, launch an asynchronous nsenter-event to enter
	// the namespaces of the process that originated the mount/umount
	// instruction. By having the 'root' path of this new nsexec process
	// matching the default one ("/"), we can now launch a subsequent nsenter
	// event to extract the mountinfo state present in the entire mount-ns.
	// Having this complete picture will probe usual later on when trying to
	// validate the legitimacy of the original mount/unmount request.
	asyncEvent := mi.service.nss.NewEvent(
		mi.process.Pid(),
		&domain.AllNSs,
		&domain.NSenterMessage{
			Type:    domain.SleepRequest,
			Payload: &domain.SleepReqPayload{Ival: strconv.Itoa(5)},
		},
		nil,
		true,
	)

	// Launch aync nsenter-event.
	err := mi.service.nss.SendRequestEvent(asyncEvent)
	if err != nil {
		return nil, err
	}
	defer asyncEvent.TerminateRequest()

	asyncEventPid := mi.service.nss.GetEventProcessID(asyncEvent)
	if asyncEventPid == 0 {
		return nil, fmt.Errorf("Invalid nsexec process agent")
	}

	// Create nsenter-event envelope. Notice that we are passing the async
	// event's pid as the one for which the mountInfo data will be collected.
	event := mi.service.nss.NewEvent(
		asyncEventPid,
		&domain.AllNSs,
		&domain.NSenterMessage{Type: domain.MountInfoRequest},
		nil,
		false,
	)

	// Launch nsenter-event.
	err = mi.service.nss.SendRequestEvent(event)
	if err != nil {
		return nil, err
	}

	// Obtain nsenter-event response.
	responseMsg := mi.service.nss.ReceiveResponseEvent(event)
	if responseMsg.Type == domain.ErrorResponse {
		return nil, fmt.Errorf("nsenter error received")
	}

	return []byte(responseMsg.Payload.(domain.MountInfoRespPayload).Data), nil
}

func (mi *mountInfoParser) extractAllInodes() error {

	var reqMounts []string

	for _, info := range mi.idInfo {
		//
		if _, ok := mi.service.mh.mapMounts[info.MountPoint]; ok == true {
			continue
		}

		reqMounts = append(reqMounts, info.MountPoint)
	}

	respMounts, err := mi.extractInodes(reqMounts)
	if err != nil {
		return nil
	}

	if len(reqMounts) != len(respMounts) {
		return fmt.Errorf("Unexpected number of inodes rcvd, expected %d, rcvd %d",
			len(reqMounts), len(respMounts))
	}

	for i := 0; i < len(reqMounts); i++ {
		info, ok := mi.mpInfo[reqMounts[i]]
		if !ok {
			return fmt.Errorf("Missing mountInfo entry for mountpoint %s",
				reqMounts[i])
		}

		info.MpInode = respMounts[i]
	}

	return nil
}

func (mi *mountInfoParser) extractAncestorInodes(info *domain.MountInfo) error {

	var reqMounts []string

	for {
		if info == nil {
			break
		}

		//
		if _, ok := mi.service.mh.mapMounts[info.MountPoint]; ok == false {
			reqMounts = append(reqMounts, info.MountPoint)
		}

		info = mi.GetParentMount(info)
	}

	respMounts, err := mi.extractInodes(reqMounts)
	if err != nil {
		return nil
	}

	if len(reqMounts) != len(respMounts) {
		return fmt.Errorf("Unexpected number of inodes rcvd, expected %d, rcvd %d",
			len(reqMounts), len(respMounts))
	}

	for i := 0; i < len(reqMounts); i++ {
		info, ok := mi.mpInfo[reqMounts[i]]
		if !ok {
			return fmt.Errorf("Missing mountInfo entry for mountpoint %s",
				reqMounts[i])
		}

		info.MpInode = respMounts[i]
	}

	return nil
}

func (mi *mountInfoParser) extractInodes(mps []string) ([]domain.Inode, error) {

	// Create nsenter-event envelope. Notice that we are passing the container's
	// initPid as the pid over which to obtain the mountInfo data.
	nss := mi.service.nss
	event := nss.NewEvent(
		mi.process.Pid(),
		&domain.AllNSsButUser,
		&domain.NSenterMessage{
			Type: domain.MountInodeRequest,
			Payload: &domain.MountInodeReqPayload{
				Mountpoints: mps,
			},
		},
		nil,
		false,
	)

	// Launch nsenter-event.
	err := nss.SendRequestEvent(event)
	if err != nil {
		return nil, err
	}

	// Obtain nsenter-event response.
	responseMsg := nss.ReceiveResponseEvent(event)
	if responseMsg.Type == domain.ErrorResponse {
		return nil, fmt.Errorf("nsenter error received")
	}

	return responseMsg.Payload.(domain.MountInodeRespPayload).MpInodes, nil
}

// isSysboxfsBasemount checks if the given mountpoint is a sysbox-fs managed
// base mount (e.g., a procfs or sysfs mountpoint).
func (mi *mountInfoParser) isSysboxfsBaseMount(info *domain.MountInfo) bool {
	return (info.FsType == "proc" || info.FsType == "sysfs") && info.Root == "/"
}

// isSysboxfsSubmountOf checks is the given mountpoint is a sysbox-fs managed
// submount of the given sysbox-fs base mount (e.g., /proc/sys is a sysbox-fs
// managed submount of /proc).
func (mi *mountInfoParser) isSysboxfsSubMountOf(info, baseInfo *domain.MountInfo) bool {
	if info.ParentID != baseInfo.MountID {
		return false
	}

	// Note: submounts may contain mounts *not* managed by sysbox-fs (e.g., if a
	// user mounts something under /proc/*). Check if the given submount is
	// managed by sysbox-fs or not.

	relMountpoint := strings.TrimPrefix(info.MountPoint, baseInfo.MountPoint)

	switch baseInfo.FsType {
	case "proc":
		if isMountpointUnder(relMountpoint, mi.service.mh.procMounts) ||
			isMountpointUnder(relMountpoint, mi.cntr.ProcRoPaths()) ||
			isMountpointUnder(relMountpoint, mi.cntr.ProcMaskPaths()) {
			return true
		}
	case "sysfs":
		if isMountpointUnder(relMountpoint, mi.service.mh.sysMounts) {
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
func (mi *mountInfoParser) isSysboxfsSubMount(info *domain.MountInfo) bool {

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
func (mi *mountInfoParser) GetInfo(mountpoint string) *domain.MountInfo {
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

// IsSysboxfsRoSubmount checks if the given mountpoint is a sysbox-fs managed
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

// IsRoMount checks if the passed mountpoint is currently present and tagged as
// read-only.
func (mi *mountInfoParser) IsRoMount(mountpoint string) bool {

	info := mi.GetInfo(mountpoint)
	if info == nil {
		return false
	}

	perMountFlags := mi.service.mh.StringToFlags(info.Options)

	return perMountFlags&unix.MS_RDONLY == unix.MS_RDONLY
}

// IsRecursiveBindMount verifies if the passed mountinfo entry is a recursive
// bind-mount.
//
// Example: [ mouuntID-3413 is a recursive bind-mount of mountID-3544 ]
//
// 3544 3503 0:129 / /usr/src/linux-headers-5.4.0-48 ro,relatime - shiftfs /usr/src/linux-headers-5.4.0-48 rw
// 3413 3544 0:129 / /usr/src/linux-headers-5.4.0-48 ro,relatime - shiftfs /usr/src/linux-headers-5.4.0-48 rw
func (mi *mountInfoParser) IsRecursiveBindMount(info *domain.MountInfo) bool {

	devIdSlice := mi.devIdInfo[info.MajorMinorVer]

	for _, elem := range devIdSlice {
		if elem.MountID == info.MountID {
			continue
		}

		if elem.MountID == info.ParentID &&
			elem.Source == info.Source &&
			elem.Root == info.Root {
			return true
		}
	}

	return false
}

// IsBindMount verifies if the passed mountinfo entry is a bind-mount.
func (mi *mountInfoParser) IsBindMount(info *domain.MountInfo) bool {

	mh := mi.service.mh
	if mh == nil {
		return false
	}

	devIdSlice := mi.devIdInfo[info.MajorMinorVer]

	for _, elem := range devIdSlice {
		if elem.MountID == info.MountID {
			continue
		}

		if elem.Root == info.Root && elem.Source == info.Source {
			return true
		}
	}

	return false
}

// IsBindMount verifies if the passed mountinfo entry is a read-only bind-mount.
func (mi *mountInfoParser) IsRoBindMount(info *domain.MountInfo) bool {

	mh := mi.service.mh
	if mh == nil {
		return false
	}

	devIdSlice := mi.devIdInfo[info.MajorMinorVer]

	for _, elem := range devIdSlice {
		if elem.MountID == info.MountID {
			continue
		}

		if elem.Root == info.Root && elem.Source == info.Source {
			return mh.StringToFlags(elem.Options)&unix.MS_RDONLY == unix.MS_RDONLY
		}
	}

	return false
}

// LookupByMountID does a simple lookup in IdInfo map.
func (mi *mountInfoParser) LookupByMountID(id int) *domain.MountInfo {

	if info, ok := mi.idInfo[id]; ok == true {
		return info
	}

	return nil
}

// LookupByMountpoint does a simple lookup in mpInfo map.
func (mi *mountInfoParser) LookupByMountpoint(mp string) *domain.MountInfo {

	if info, ok := mi.mpInfo[mp]; ok == true {
		return info
	}

	return nil
}
