//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

package domain

import "os"

type Inode = uint64

//
// ioNode interface serves as an abstract-class to represent all I/O resources
// with whom sysbox-fs operates. All I/O transactions will be carried out
// through the methods exposed by this interface and its derived sub-classes.
// There are two specializations of this interface at the moment:
//
// 1. ioNodeFile: Basically, a wrapper over os.File type to allow interactions
//    with the host FS. To be utilized in production scenarios.
//
// 2. ioNodeBuffer: An enhanced byte-buffer class wrapper. To be utilized
//    during UT efforts.
//

type IOnode interface {
	Open() error
	Read(p []byte) (n int, err error)
	Write(p []byte) (n int, err error)
	Close() error
	ReadAt(p []byte, off int64) (n int, err error)
	ReadDirAll() ([]os.FileInfo, error)
	ReadFile() ([]byte, error)
	ReadLine() (string, error)
	Stat() (os.FileInfo, error)
	SeekReset() (int64, error)
	//
	// Required getters/setters.
	//
	Name() string
	Path() string
	OpenFlags() int
	SetOpenFlags(flags int)
}

type IOService interface {
	NewIOnode(n string, p string, attr os.FileMode) IOnode
	OpenNode(i IOnode) error
	ReadNode(i IOnode, p []byte) (int, error)
	WriteNode(i IOnode, p []byte) (int, error)
	CloseNode(i IOnode) error
	ReadAtNode(i IOnode, p []byte, off int64) (int, error)
	ReadDirAllNode(i IOnode) ([]os.FileInfo, error)
	ReadFileNode(i IOnode) ([]byte, error)
	ReadLineNode(i IOnode) (string, error)
	StatNode(i IOnode) (os.FileInfo, error)
	SeekResetNode(i IOnode) (int64, error)
	PathNode(i IOnode) string
}
