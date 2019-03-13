package main

import (
	"fmt"
	"os"
	"syscall"
	"time"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
)

var sysvisorfs *sysvisorFS

//
// sysvisorFS struct
//
type sysvisorFS struct {
	root         *Dir
	path         string
	size         int64
	cntrMap      containerMap
	pidNsCntrMap pidNsContainerMap
}

//
// newSysvisorFS constructor
//
func newSysvisorFS(path string) *sysvisorFS {

	info, err := os.Stat(path)
	if err != nil {
		fmt.Println("File-System path \"", path, "\" not found")
		return nil
	}

	newfs := &sysvisorFS{
		path: path,
		root: nil,
		size: 0,
	}

	//
	// Creating a first node corresponding to the root element in
	// sysvisorFS.
	//
	attr := StatToAttr(info.Sys().(*syscall.Stat_t))
	attr.Mode = os.ModeDir | os.FileMode(int(0777))
	newfs.root = NewDir(path, &attr)

	//
	// Initializing container-related data-structs
	//
	newfs.cntrMap = *newContainerMap(newfs)
	newfs.pidNsCntrMap = *newPidNsContainerMap()

	return newfs
}

//
// Root method. This is a FUSE-lib requirement. Function returns sysvisor-fs'
// root-node.
//
func (f *sysvisorFS) Root() (fs.Node, error) {
	return f.root, nil
}

//
// StatToAttr helper function to translate FS node-parameters from unix/kernel
// format to FUSE ones.
//
// Kernel FS node attribs:  fuse.attr (fuse_kernel*.go)
// FUSE node attribs:       fuse.Attr (fuse.go)
//
// TODO: Place me in a more appropiate location
//
func StatToAttr(s *syscall.Stat_t) fuse.Attr {

	var a fuse.Attr

	a.Inode = uint64(s.Ino)
	a.Size = uint64(s.Size)
	a.Blocks = uint64(s.Blocks)

	a.Atime = time.Unix(s.Atim.Sec, s.Atim.Nsec)
	a.Mtime = time.Unix(s.Mtim.Sec, s.Mtim.Nsec)
	a.Ctime = time.Unix(s.Ctim.Sec, s.Ctim.Nsec)

	a.Mode = os.FileMode(s.Mode)
	a.Nlink = uint32(s.Nlink)
	a.Uid = uint32(s.Uid)
	a.Gid = uint32(s.Gid)
	a.Rdev = uint32(s.Rdev)
	a.BlockSize = uint32(s.Blksize)

	return a
}
