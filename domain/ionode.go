package domain

import "os"

type Inode = uint64

//var AppFs = afero.NewOsFs()

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

type IOnodeOps interface {
	Open(i IOnode) error
	Read(i IOnode, p []byte) (n int, err error)
	Write(i IOnode, p []byte) (n int, err error)
	Close(i IOnode) error
	ReadAt(i IOnode, p []byte, off int64) (n int, err error)
	ReadDirAll(i IOnode) ([]os.FileInfo, error)
	SetOpenFlags(flags int)
	GetOpenFlags() int
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

/*
type IOnode struct{}

type IOnodeIntf interface {
	//IOnodeOpener
	io.Reader
	io.Writer
	io.Closer
	io.ReaderAt
	//IOnodeDirReader
}

type IOnodeConfig interface{}

type IOnodeOpener interface {
	Open(c IOnodeConfig) IOnodeIntf
}

type IOnodeReader interface {
	//Read(i *IOnode, p []byte) (n int, err error)
	io.Reader
}

type IOnodeWriter interface {
	//Write(i *IOnode, p []byte) (n int, err error)
	io.Writer
}

type IOnodeCloser interface {
	//Close(i *IOnode) error
	io.Closer
}

type IOnodeReadAter interface {
	//ReadAt(i *IOnode, p []byte, off int64) (n int, err error)
	io.ReaderAt
}

type IOnodeDirReader interface {
	DirAll(i *IOnodeIntf) (n int, err error)
}

type nodeType int

const (
	Unknown nodeType = iota
	FileNode
	HandlerNode
	BufferNode
)

// Interface-factory function to serve as a common constructor for all ioNode
// types.
func NewNode(t nodeType, config IOnodeConfig) IOnodeIntf {

	switch t {

	case FileNode:
		return newNodeFile(config)

	case HandlerNode:
		//return newNodeHandler(config)

	case BufferNode:
		//return newNodeBuffer(config)

	default:
		log.Panicf("Unsupported ioNode: %v", t)
	}

	return nil
}
*/

/*
type IOnodeOps interface {
	// io.Reader
	// io.Writer
	// io.Closer
	// io.ReaderAt
	// Read(i *IOnode, p []byte) (n int, err error)
	// Write(i *IOnode, p []byte) (n int, err error)
	// Close(i *IOnode) error
	// ReadAt(i *IOnode, p []byte, off int64) (n int, err error)
	IOnodeOpener
	IOnodeReader
	IOnodeWriter
	IOnodeCloser
	IOnodeReadAter
	//IOnodeDirAllReader
}
*/

/*
type nodeType int

const (
	Unknown nodeType = iota
	FileNode
	HandlerNode
	BufferNode
)

type IOconfig interface{}

type IOnode interface {
	io.Reader
	io.Writer
	io.Closer
}

// Interface-factory function to serve as a common constructor for all ioNode
// types.
func NewNode(t nodeType, config IOconfig) IOnode {

	switch t {

	case FileNode:
		return newNodeFile(config)

	case HandlerNode:
		//return newNodeHandler(config)

	case BufferNode:
		return newNodeBuffer(config)

	default:
		log.Panicf("Unsupported ioNode: %v", t)
	}

	return nil
}
*/

/*

type file struct {
	path Path
	//ionode ionode
}

type FileService interface {
	File(p Path) (*File, error)
	CreateFile(file *File) error
	ReadFile(file *File) error
	WriteFile(file *File) error
}

*/
