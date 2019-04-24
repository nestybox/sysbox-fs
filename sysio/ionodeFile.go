package sysio

import (
	"bufio"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/nestybox/sysvisor/sysvisor-fs/domain"
)

// Ensure IOnodeFile implements IOnode's interface.
//var _ IOnode = (*IOnodeFile)(nil)
//var _ IOnodeOps = (*IOnodeFileOps)(nil)

type ioFileService struct{}

func (s *ioFileService) NewIOnode(p string, attr os.FileMode) domain.IOnode {
	newFile := &IOnodeFile{
		Path: p,
		Attr: 0644,
	}

	return newFile
}

func (s *ioFileService) OpenNode(i domain.IOnode) error {
	return i.Open()
}

func (s *ioFileService) ReadNode(i domain.IOnode, p []byte) (int, error) {
	return i.Read(p)
}

func (s *ioFileService) WriteNode(i domain.IOnode, p []byte) (int, error) {
	return i.Write(p)
}

func (s *ioFileService) CloseNode(i domain.IOnode) error {
	return i.Close()
}

func (s *ioFileService) ReadAtNode(i domain.IOnode, p []byte, off int64) (int, error) {
	return i.ReadAt(p, off)
}

func (s *ioFileService) ReadDirAllNode(i domain.IOnode) ([]os.FileInfo, error) {
	return i.ReadDirAll()
}

func (s *ioFileService) ReadLineNode(i domain.IOnode) string {
	return i.ReadLine()
}

func (s *ioFileService) SeekResetNode(i domain.IOnode) (int64, error) {
	return i.SeekReset()
}

func (s *ioFileService) PidNsInode(i domain.IOnode) (domain.Inode, error) {
	return i.PidNsInode()
}

//
//
//
type IOnodeFile struct {
	Path  string
	Flags int
	Attr  os.FileMode
	File  *os.File
}

//func newIOnodeFile() domain.IOnodeIface {
//	return &IOnodeFile{}
//}

func (i *IOnodeFile) Open() error {

	file, err := os.OpenFile(i.Path, i.Flags, i.Attr)
	if err != nil {
		return err
	}

	i.File = file

	return nil
}

func (i *IOnodeFile) Read(p []byte) (n int, err error) {
	return i.File.Read(p)
}

func (i *IOnodeFile) Write(p []byte) (n int, err error) {
	return i.File.Write(p)
}

func (i *IOnodeFile) Close() error {
	return i.File.Close()
}

func (i *IOnodeFile) ReadAt(p []byte, off int64) (n int, err error) {
	return i.File.ReadAt(p, off)
}

func (i *IOnodeFile) ReadDirAll() ([]os.FileInfo, error) {
	return ioutil.ReadDir(i.Path)
}

func (i *IOnodeFile) SetOpenFlags(flags int) {
	i.Flags = flags
}

func (i *IOnodeFile) GetOpenFlags() int {
	return i.Flags
}

func (i *IOnodeFile) ReadLine() string {
	scanner := bufio.NewScanner(i.File)
	scanner.Scan()
	return scanner.Text()
}

func (i *IOnodeFile) SeekReset() (int64, error) {
	return i.File.Seek(0 /*os.SEEK_SET*/, 0)
}

func (i *IOnodeFile) PidNsInode() (domain.Inode, error) {

	pid, err := strconv.Atoi(i.Path)
	if err != nil {
		return 0, err
	}

	pidnsPath := strings.Join([]string{
		"/proc",
		strconv.FormatUint(uint64(pid), 10),
		"ns/pid"}, "/")

	// Extract pid-ns info from FS.
	info, err := os.Stat(pidnsPath)
	if err != nil {
		log.Println("No process file found for pid:", pid)
		return 0, err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		log.Println("Not a syscall.Stat_t")
		return 0, nil
	}

	return stat.Ino, nil
}

/*

type IOnodeFileOps struct{}

func (ops *IOnodeFileOps) Open(i IOnode) error {
	return i.Open()
}

func (ops *IOnodeFileOps) Read(i IOnode, p []byte) (n int, err error) {
	return i.Read(p)
}

func (ops *IOnodeFileOps) Write(i IOnode, p []byte) (n int, err error) {
	return i.Write(p)
}

func (ops *IOnodeFileOps) Close(i IOnode) error {
	return i.Close()
}

func (ops *IOnodeFileOps) ReadAt(i IOnode, p []byte, off int64) (n int, err error) {
	return i.ReadAt(p, off)
}

func (ops *IOnodeFileOps) ReadDirAll(i IOnode) ([]os.FileInfo, error) {
	return i.ReadDirAll()
}

func (ops *IOnodeFileOps) SetOpenFlags(flags int) {
	ops.SetOpenFlags(flags)
}

func (ops *IOnodeFileOps) GetOpenFlags() int {
	return ops.GetOpenFlags()
}

//
//
//
type IOnodeFile struct {
	Path  string
	Flags int
	Attr  os.FileMode
	File  *os.File
}

func (i *IOnodeFile) Open() error {

	file, err := os.OpenFile(i.Path, i.Flags, i.Attr)
	if err != nil {
		return err
	}

	i.File = file

	return nil
}

func NewIOnodeFile() *IOnodeFile {
	return &IOnodeFile{}
}

func (i *IOnodeFile) Read(p []byte) (n int, err error) {
	return i.File.Read(p)
}

func (i *IOnodeFile) Write(p []byte) (n int, err error) {
	return i.File.Write(p)
}

func (i *IOnodeFile) Close() error {
	return i.File.Close()
}

func (i *IOnodeFile) ReadAt(p []byte, off int64) (n int, err error) {
	return i.File.ReadAt(p, off)
}

func (i *IOnodeFile) ReadDirAll() ([]os.FileInfo, error) {
	return ioutil.ReadDir(i.Path)
}

func (i *IOnodeFile) SetOpenFlags(flags int) {
	i.Flags = flags
}

func (i *IOnodeFile) GetOpenFlags() int {
	return i.Flags
}

/*
func (op *IOnodeFileOps) Open(i *IOnode) error {

	config := i.Config.(*IOnodeConfigFile)
	if config == nil {
		return nil
	}

	file, err := os.OpenFile(config.Path, int(config.Flags), config.Attr)
	if err != nil {
		return err
	}

	i.Config.(*IOnodeConfigFile).File = file

	return nil
}

func (op *IOnodeFileOps) Read(i *IOnode, p []byte) (n int, err error) {

	return i.Config.(*IOnodeConfigFile).File.Read(p)
}

func (op *IOnodeFileOps) Write(i *IOnode, p []byte) (n int, err error) {

	return i.Config.(*IOnodeConfigFile).File.Write(p)
}

func (op *IOnodeFileOps) Close(i *IOnode) error {

	return i.Config.(*IOnodeConfigFile).File.Close()
}

func (op *IOnodeFileOps) ReadAt(i *IOnode, p []byte, off int64) (n int, err error) {

	return i.Config.(*IOnodeConfigFile).File.ReadAt(p, off)
}

func (op *IOnodeFileOps) ReadDirAll(i *IOnode) ([]os.FileInfo, error) {

	return ioutil.ReadDir(i.Config.(*IOnodeConfigFile).Path)
}
*/

/*
func (i *IOnodeFile) Open() error {

	file, err := os.OpenFile(config.Path, int(config.Flags), config.Attr)
	if err != nil {
		return error
	}

	newNode := &IOnodeFile{
		Config: config,
		File:   file,
	}

	return nil
}

func (i *IOnodeFile) Read(p []byte) (n int, err error) {

	return i.File.Read(p)
}

func (i *IOnodeFile) Write(p []byte) (n int, err error) {

	return i.File.Write(p)
}

func (i *IOnodeFile) Close() error {

	return i.File.Close()
}

func (i *IOnodeFile) ReadAt(p []byte, off int64) (n int, err error) {

	return i.File.ReadAt(p, off)
}

func (i *IOnodeFile) DirAll() ([]os.FileInfo, error) {

	return ioutil.ReadDir(i.Config.Path)
}
*/

//Write(i *IOnode, p []byte) (n int, err error)
//Close(i *IOnode) error
//ReadAt(i *IOnode, p []byte, off int64) (n int, err error)

// ioNodeFile specialization. Utilized in production scenarios.

/*
type IOnodeConfigFile struct {
	Path  string
	Flags int
	Attr  os.FileMode
}


type IOnodeFileService struct {
	// path   string
	// flags  int
	// attr   os.FileMode
	// reader   io.Reader
	// writer   io.Writer
	// closer   io.Closer
	// readerat io.ReaderAt

	reader   IOnodeReader
	writer   IOnodeWriter
	closer   IOnodeCloser
	readerat IOnodeReadAter
	//ops IOnodeOps
}
*/
/*
type IOnodeFile struct {
	reader   IOnodeReader
	writer   IOnodeWriter
	closer   IOnodeCloser
	readerat IOnodeReadAter

	//reader   io.Reader
	//readerat io.ReaderAt
	//writer   io.Writer
	//closer   io.Closer
}

// IOnodeFile constructor.
func newNodeFile(config IOnodeConfig) IOnodeIntf {

	var (
		newNode IOnodeIntf
		err     error
	)

	c := config.(*IOnodeConfigFile)
	if config == nil {
		return nil
	}

	newNode, err = os.OpenFile(c.Path, int(c.Flags), c.Attr)
	if err != nil {
		return nil
	}

	return newNode
}

// Regular read() instruction to obtain state from host FS.
func (i *IOnodeFile) Read(p []byte) (int, error) {

	n, err := i.reader.Read(p)
	if err != nil && err != io.EOF {
		log.Println("Read ERR:", err)
		return 0, err
	}

	return n, nil
}

// Regular readAt() instruction to obtain state from host FS.
func (i *IOnodeFile) ReadAt(p []byte, offset int64) (int, error) {

	n, err := i.readerat.ReadAt(p, offset)
	if err != nil && err != io.EOF {
		log.Println("Read ERR:", err)
		return 0, err
	}

	return n, nil
}

// Regular write() instruction to inject state into host FS.
func (i *IOnodeFile) Write(p []byte) (n int, err error) {

	n, err = i.writer.Write(p)
	if err != nil {
		log.Println("Write ERR:", err)
		return 0, err
	}

	return n, nil
}

// Regular close() instruction for host FS.
func (i *IOnodeFile) Close() error {
	return i.closer.Close()
}

/*
func Open(c IOnodeConfigFile) IOnodeIntf {

	// var (
	// 	newNode IOnodeFile
	// 	err     error
	// )

	// config := cfg.(*ioConfigFile)
	// if config == nil {
	// 	return nil
	// }

	var (
		fh  io.Reader
		err error
	)
	fh, err = os.OpenFile(c.path, int(c.flags), c.attr)
	//fh, err = os.OpenFile("Testing", 1, 2)
	if err != nil {
		return nil
	}

	//var newNode IOnodeIntf = file
	newNode := &IOnodeFile{
		path:   c.path,
		flags:  c.flags,
		attr:   c.attr,
		reader: fh,
	}

	return newNode
}

// Regular read() file-system instruction.
func (op IOnodeFile) Read(p []byte) (int, error) {

	//n, err := op.reader.Read(p)
	n, err := op.handle.Read(p)
	if err != nil && err != io.EOF {
		log.Println("Read ERR:", err)
		return 0, err
	}

	return n, nil
}

/*
// Regular read() file-system instruction.
// func (op IOnodeFile) Read(p []byte) (int, error) {

// 	n, err := op.reader.Read(p)
// 	if err != nil && err != io.EOF {
// 		log.Println("Read ERR:", err)
// 		return 0, err
// 	}

// 	return n, nil
// }

// Regular readAt() file-system instruction.
func (i IOnodeFile) ReadAt(p []byte, offset int64) (int, error) {

	n, err := i.readerat.ReadAt(p, offset)
	if err != nil && err != io.EOF {
		log.Println("Read ERR:", err)
		return 0, err
	}

	return n, nil
}

// Regular write() file-system instruction.
func (i IOnodeFile) Write(p []byte) (n int, err error) {

	n, err = i.writer.Write(p)
	if err != nil {
		log.Println("Write ERR:", err)
		return 0, err
	}

	return n, nil
}

// Regular close() instruction for host FS.
func (i IOnodeFile) Close() error {
	return i.closer.Close()
}
*/

/*
type ioConfigFile struct {
	path  string
	flags int
	attr  os.FileMode
}

// ioNodeFile specialization. Utilized in production scenarios.
type ioNodeFile struct {
	reader   io.Reader
	writer   io.Writer
	closer   io.Closer
	readerat io.ReaderAt
}

// ioNodeFile constructor.
func newNodeFile(cfgIntf IOconfig) IOnode {

	var (
		newNode IOnode
		err     error
	)

	config := cfgIntf.(*ioConfigFile)
	if config == nil {
		return nil
	}

	newNode, err = os.OpenFile(config.path, int(config.flags), config.attr)
	if err != nil {
		return nil
	}

	return newNode
}

// Regular read() file-system instruction.
func (i *ioNodeFile) Read(p []byte) (int, error) {

	n, err := i.reader.Read(p)
	if err != nil && err != io.EOF {
		log.Println("Read ERR:", err)
		return 0, err
	}

	return n, nil
}

// Regular readAt() file-system instruction.
func (i *ioNodeFile) ReadAt(p []byte, offset int64) (int, error) {

	n, err := i.readerat.ReadAt(p, offset)
	if err != nil && err != io.EOF {
		log.Println("Read ERR:", err)
		return 0, err
	}

	return n, nil
}

// Regular write() file-system instruction.
func (i *ioNodeFile) Write(p []byte) (n int, err error) {

	n, err = i.writer.Write(p)
	if err != nil {
		log.Println("Write ERR:", err)
		return 0, err
	}

	return n, nil
}

// Regular close() instruction for host FS.
func (i *ioNodeFile) Close() error {
	return i.closer.Close()
}
*/
