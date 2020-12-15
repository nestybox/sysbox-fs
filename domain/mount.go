//
// Copyright 2020 Nestybox, Inc.
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

package domain

// Service interface to expose mount-service's components.
type MountServiceIface interface {
	Setup(
		css ContainerStateServiceIface,
		hds HandlerServiceIface)

	NewMountInfoParser(c ContainerIface, pid uint32, deep bool) (MountInfoParserIface, error)
	NewMountHelper() MountHelperIface
	MountHelper() MountHelperIface
}

// Interface to define the mountInfoParser api.
type MountInfoParserIface interface {
	GetInfo(mountpoint string) *MountInfo
	LookupByMountID(id int) *MountInfo
	LookupByMountpoint(mp string) *MountInfo
	IsSysboxfsBaseMount(mountpoint string) bool
	IsSysboxfsSubmount(mountpoint string) bool
	IsSysboxfsRoSubmount(mountpoint string) bool
	IsSysboxfsMaskedSubmount(mountpoint string) bool
	GetSysboxfsSubMounts(basemount string) []string
	HasNonSysboxfsSubmount(basemount string) bool
	IsRecursiveBindMount(info *MountInfo) bool
	IsRoMount(mountpoint string) bool
	IsBindMount(info *MountInfo) bool
	IsRoBindMount(info *MountInfo) bool
}

// Interface to define the mountHelper api.
type MountHelperIface interface {
	IsNewMount(flags uint64) bool
	IsRemount(flags uint64) bool
	IsBind(flags uint64) bool
	IsMove(flags uint64) bool
	HasPropagationFlag(flags uint64) bool
	IsReadOnlyMount(flags uint64) bool
	StringToFlags(s map[string]string) uint64
	FilterFsFlags(fsOpts map[string]string) string
	ProcMounts() []string
	SysMounts() []string
}

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
type MountInfo struct {
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

// Mount structure utilized to exchange mount-state across sysbox-fs components.
type Mount struct {
	Source string `json:"source"`
	Target string `json:"target"`
	FsType string `json:"fstype"`
	Flags  uint64 `json:"flags"`
	Data   string `json:"data"`
}
