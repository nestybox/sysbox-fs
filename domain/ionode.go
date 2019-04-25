package domain

import "os"

type Inode = uint64

//
// ioNode interface serves as an abstract-class to represent all I/O resources
// with whom sysvisor-fs operates. All I/O transactions will be carried out
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
	SetOpenFlags(flags int)
	GetOpenFlags() int
	ReadLine() string
	SeekReset() (int64, error)
	PidNsInode() (Inode, error)
}

type IOService interface {
	NewIOnode(p string, attr os.FileMode) IOnode
	OpenNode(i IOnode) error
	ReadNode(i IOnode, p []byte) (int, error)
	WriteNode(i IOnode, p []byte) (int, error)
	CloseNode(i IOnode) error
	ReadAtNode(i IOnode, p []byte, off int64) (int, error)
	ReadDirAllNode(i IOnode) ([]os.FileInfo, error)
	ReadLineNode(i IOnode) string
	SeekResetNode(i IOnode) (int64, error)
	PidNsInode(i IOnode) (Inode, error)
}
