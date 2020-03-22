//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

package domain

import "reflect"

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
	SetCapability(which CapType, what ...Cap)
	IsCapabilitySet(which CapType, what Cap) bool
	NsInodes() map[string]Inode
	UserNsInode() Inode
	UserNsInodeParent() (Inode, error)
	PathAccess(path string, accessFlags AccessMode) error
	Camouflage(
		uid uint32,
		gid uint32,
		capDacRead bool,
		capDacOverride bool) error
}

type ProcessService interface {
	ProcessCreate(pid uint32, uid uint32, gid uint32) ProcessIface
}

// ProcessNsMatch returns true if the given processes are in the same namespaces.
func ProcessNsMatch(p1, p2 ProcessIface) bool {
	return reflect.DeepEqual(p1.NsInodes(), p2.NsInodes())
}
