package main

import (
	"fmt"
	"os"

	"bazil.org/fuse/fs"
)

var sysvisorfs *SysvisorFS

//
// SysvisorFS struct
//
type SysvisorFS struct {
	root *Dir
	path string
	size int64
}

//
// NewSysvisorFS constructor
//
func NewSysvisorFS(path string) *SysvisorFS {

	_, err := os.Stat(path)
	if err != nil {
		fmt.Println("File-System path \"", path, "\" not found")
		return nil
	}

	newfs := &SysvisorFS{
		path: path,
		root: nil,
		size: 0,
	}

	return newfs
}

//
// Root method. This is a FUSE lib requirement. Function returns FS root-node.
//
func (f *SysvisorFS) Root() (fs.Node, error) {
	return f.root, nil
}
