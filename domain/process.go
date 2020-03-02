//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

package domain

const (
	SymlinkMax = 40
)

type AccessMode uint32

const (
	R_OK AccessMode = 0x4 // read ok
	W_OK AccessMode = 0x2 // write ok
	X_OK AccessMode = 0x1 // execute ok
)

type ProcessIface interface {
	Pid() uint32
	Uid() uint32
	Gid() uint32
	Capabilities() error
	SetCapability(which uint, what ...int)
	IsCapabilitySet(which uint, what int) bool
	PidNsInode() (Inode, error)
	PidNsInodeParent() (Inode, error)
	PathAccess(path string, accessFlags int) error
	Camouflage(
		uid uint32,
		gid uint32,
		capDacRead bool,
		capDacOverride bool) error
}

type ProcessService interface {
	ProcessCreate(pid uint32, uid uint32, gid uint32) ProcessIface
}
