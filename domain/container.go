//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

package domain

import "time"

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
	PidInode() Inode
	Data(path string, name string) (string, bool)
	String() string
	UID() uint32
	GID() uint32
	ProcRoPaths() []string
	ProcMaskPaths() []string
	//
	// Setters
	//
	SetData(path string, name string, data string)
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
type ContainerStateService interface {
	ContainerCreate(
		id string,
		pid uint32,
		pidNsInode Inode,
		ctime time.Time,
		uidFirst uint32,
		uidSize uint32,
		gidFirst uint32,
		gidSize uint32,
		procRoPaths []string,
		procMaskPaths []string) ContainerIface

	ContainerAdd(c ContainerIface) error
	ContainerUpdate(c ContainerIface) error
	ContainerDelete(c ContainerIface) error
	ContainerLookupById(id string) ContainerIface
	ContainerLookupByInode(pidInode Inode) ContainerIface
	ContainerLookupByPid(pid uint32) ContainerIface
}
