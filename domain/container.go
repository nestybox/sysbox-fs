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

package domain

import (
	"time"

	libpidfd "github.com/nestybox/sysbox-libs/pidfd"
)

// Container interface.
type ContainerIface interface {
	//
	// Getters
	//
	ID() string
	InitPid() uint32
	InitPidFd() libpidfd.PidFd
	Ctime() time.Time
	Data(name string, offset int64, data *[]byte) (int, error)
	UID() uint32
	GID() uint32
	UidSize() uint32
	GidSize() uint32
	ProcRoPaths() []string
	ProcMaskPaths() []string
	InitProc() ProcessIface
	ExtractInode(path string) (Inode, error)
	IsMountInfoInitialized() bool
	InitializeMountInfo() error
	IsRootMount(info *MountInfo) (bool, error)
	IsRootMountID(id int) (bool, error)
	IsImmutableMount(info *MountInfo) (bool, error)
	IsImmutableRoMount(info *MountInfo) (bool, error)
	IsImmutableMountID(id int) bool
	IsImmutableRoMountID(id int) bool
	IsImmutableBindMount(info *MountInfo) bool
	IsImmutableRoBindMount(info *MountInfo) bool
	IsImmutableMountpoint(mp string) bool
	IsImmutableRoMountpoint(mp string) bool
	IsImmutableOverlapMountpoint(mp string) bool
	IsRegistrationCompleted() bool
	//
	// Setters
	//
	SetData(name string, offset int64, data []byte) error
	SetInitProc(pid, uid, gid uint32) error
	SetRegistrationCompleted()
	//
	// Locks for read-modify-write operations on container data via the Data()
	// and SetData() methods.
	//
	Lock()
	Unlock()
}

// ContainerStateService interface defines the APIs that sysbox-fs components
// must utilize to interact with the sysbox-fs state-storage backend.
type ContainerStateServiceIface interface {
	Setup(
		fss FuseServerServiceIface,
		prs ProcessServiceIface,
		ios IOServiceIface,
		mts MountServiceIface)

	ContainerCreate(
		id string,
		pid uint32,
		ctime time.Time,
		uidFirst uint32,
		uidSize uint32,
		gidFirst uint32,
		gidSize uint32,
		procRoPaths []string,
		procMaskPaths []string,
		service ContainerStateServiceIface) ContainerIface

	ContainerPreRegister(id, netns string) error
	ContainerRegister(c ContainerIface) error
	ContainerUpdate(c ContainerIface) error
	ContainerUnregister(c ContainerIface) error
	ContainerLookupById(id string) ContainerIface
	FuseServerService() FuseServerServiceIface
	ProcessService() ProcessServiceIface
	MountService() MountServiceIface
	ContainerDBSize() int
}
