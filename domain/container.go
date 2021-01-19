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
)

//
// Container interface.
//
type ContainerIface interface {
	//
	// Getters
	//
	ID() string
	InitPid() uint32
	Ctime() time.Time
	Data(path string, name string) (string, bool)
	String() string
	UID() uint32
	GID() uint32
	ProcRoPaths() []string
	ProcMaskPaths() []string
	InitProc() ProcessIface
	ExtractInode(path string) (Inode, error)
	IsImmutableMountID(id int) bool
	IsImmutableRoMountID(id int) bool
	IsImmutableMountpoint(mp string) bool
	IsImmutableMount(info *MountInfo) bool
	IsImmutableRoMount(info *MountInfo) bool
	IsImmutableBindMount(info *MountInfo) bool
	// IsImmutableBindMount2(info *MountInfo) bool
	IsImmutableRoBindMount(info *MountInfo) bool
	//
	// Setters
	//
	SetData(path string, name string, data string)
	SetInitProc(pid, uid, gid uint32) error
	//
	// Locks for read-modify-write operations on container data via the Data()
	// and SetData() methods.
	//
	Lock()
	Unlock()
}

//
// Auxiliary types to deal with the per-container-state associated to all the
// emulated resources.
//
type StateDataMap = map[string]map[string]string
type StateData = map[string]string

//
// ContainerStateService interface defines the APIs that sysbox-fs components
// must utilize to interact with the sysbox-fs state-storage backend.
//
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

	ContainerPreRegister(id string) error
	ContainerRegister(c ContainerIface) error
	ContainerUpdate(c ContainerIface) error
	ContainerUnregister(c ContainerIface) error
	ContainerLookupById(id string) ContainerIface
	ContainerLookupByInode(usernsInode Inode) ContainerIface
	ContainerLookupByProcess(process ProcessIface) ContainerIface
	FuseServerService() FuseServerServiceIface
	ProcessService() ProcessServiceIface
	MountService() MountServiceIface
	ContainerDBSize() int
}
