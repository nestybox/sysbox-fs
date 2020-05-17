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

type IOServiceType = int

const (
	Unknown          IOServiceType = iota
	IOOsFileService                // production / regular purposes
	IOMemFileService               // unit-testing purposes
	IOBufferService
)

type IOServiceIface interface {
	NewIOnode(n string, p string, attr os.FileMode) IOnodeIface
	RemoveAllIOnodes() error
	OpenNode(i IOnodeIface) error
	ReadNode(i IOnodeIface, p []byte) (int, error)
	WriteNode(i IOnodeIface, p []byte) (int, error)
	CloseNode(i IOnodeIface) error
	ReadAtNode(i IOnodeIface, p []byte, off int64) (int, error)
	ReadDirAllNode(i IOnodeIface) ([]os.FileInfo, error)
	ReadFileNode(i IOnodeIface) ([]byte, error)
	ReadLineNode(i IOnodeIface) (string, error)
	StatNode(i IOnodeIface) (os.FileInfo, error)
	SeekResetNode(i IOnodeIface) (int64, error)
	PathNode(i IOnodeIface) string
	GetServiceType() IOServiceType
}

type IOnodeIface interface {
	Open() error
	Read(p []byte) (n int, err error)
	Write(p []byte) (n int, err error)
	Close() error
	ReadAt(p []byte, off int64) (n int, err error)
	ReadDirAll() ([]os.FileInfo, error)
	ReadFile() ([]byte, error)
	ReadLine() (string, error)
	WriteFile(p []byte) error
	Mkdir() error
	MkdirAll() error
	Stat() (os.FileInfo, error)
	SeekReset() (int64, error)
	//
	// Required getters/setters.
	//
	Name() string
	Path() string
	OpenFlags() int
	OpenMode() os.FileMode
	GetNsInode() (Inode, error)
	SetOpenFlags(flags int)
	SetOpenMode(mode os.FileMode)
}
