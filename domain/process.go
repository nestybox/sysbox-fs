
package domain

import (
	"reflect"
)

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
	IsAdminCapabilitySet() bool
	NsInodes() (map[string]Inode, error)
	UserNsInode() (Inode, error)
	UserNsInodeParent() (Inode, error)
	CreateNsInodes(Inode) error
	PathAccess(path string, accessFlags AccessMode) error
}

type ProcessServiceIface interface {
	Setup(ios IOServiceIface)
	ProcessCreate(pid uint32, uid uint32, gid uint32) ProcessIface
}

// ProcessNsMatch returns true if the given processes are in the same namespaces.
func ProcessNsMatch(p1, p2 ProcessIface) bool {
	p1Inodes, p1Err := p1.NsInodes()
	p2Inodes, p2Err := p2.NsInodes()

	if p1Err != nil || p2Err != nil {
		return false
	}

	return reflect.DeepEqual(p1Inodes, p2Inodes)
}
