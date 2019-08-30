//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

package sysio

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/spf13/afero"
)

//
var AppFs = afero.NewOsFs()

// Ensure IOnodeFile implements IOnode's interface.
var _ domain.IOnode = (*IOnodeFile)(nil)
var _ domain.IOService = (*ioFileService)(nil)

//
// I/O Service providing FS interaction capabilities.
//
type ioFileService struct{}

func (s *ioFileService) NewIOnode(n string, p string, attr os.FileMode) domain.IOnode {
	newFile := &IOnodeFile{
		name: n,
		path: p,
		attr: attr,
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

func (s *ioFileService) ReadFileNode(i domain.IOnode) ([]byte, error) {
	return i.ReadFile()
}

func (s *ioFileService) ReadLineNode(i domain.IOnode) (string, error) {
	return i.ReadLine()
}

func (s *ioFileService) StatNode(i domain.IOnode) (os.FileInfo, error) {
	return i.Stat()
}

func (s *ioFileService) SeekResetNode(i domain.IOnode) (int64, error) {
	return i.SeekReset()
}

func (s *ioFileService) PidNsInode(i domain.IOnode) (domain.Inode, error) {
	return i.PidNsInode()
}

func (s *ioFileService) PathNode(i domain.IOnode) string {
	return i.Path()
}

//
// IOnode class specialization for FS interaction.
//
type IOnodeFile struct {
	name  string
	path  string
	flags int
	attr  os.FileMode
	file  afero.File
}

func (i *IOnodeFile) Open() error {

	file, err := AppFs.OpenFile(i.path, i.flags, i.attr)
	if err != nil {
		return err
	}

	i.file = file

	return nil
}

func (i *IOnodeFile) Read(p []byte) (n int, err error) {

	if i.file == nil {
		return 0, fmt.Errorf("File not currently opened.")
	}

	return i.file.Read(p)

}

func (i *IOnodeFile) Write(p []byte) (n int, err error) {

	if i.file == nil {
		return 0, fmt.Errorf("File not currently opened.")
	}

	return i.file.Write(p)
}

func (i *IOnodeFile) Close() error {

	if i.file == nil {
		return fmt.Errorf("File not currently opened.")
	}

	return i.file.Close()
}

func (i *IOnodeFile) ReadAt(p []byte, off int64) (n int, err error) {

	if i.file == nil {
		return 0, fmt.Errorf("File not currently opened.")
	}

	return i.file.ReadAt(p, off)
}

func (i *IOnodeFile) ReadDirAll() ([]os.FileInfo, error) {
	return afero.ReadDir(AppFs, i.path)
}

func (i *IOnodeFile) ReadFile() ([]byte, error) {

	var (
		content []byte
		err     error
	)

	_, ok := AppFs.(*afero.MemMapFs)
	if ok {
		content, err = afero.ReadFile(AppFs, i.path)
		if err != nil {
			return nil, err
		}
	} else {
		content, err = ioutil.ReadFile(i.path)
		if err != nil {
			return nil, err
		}
	}

	return content, nil
}

func (i *IOnodeFile) ReadLine() (string, error) {

	var res string

	// Open file and return empty string if an error is received.
	inFile, err := AppFs.Open(i.path)
	if err != nil {
		return res, err
	}
	defer inFile.Close()

	// Rely on bufio scanner to be able to break file in lines.
	scanner := bufio.NewScanner(inFile)
	scanner.Split(bufio.ScanLines)
	scanner.Scan()
	res = scanner.Text()

	return res, nil
}

func (i *IOnodeFile) Stat() (os.FileInfo, error) {
	return AppFs.Stat(i.path)
}

func (i *IOnodeFile) SeekReset() (int64, error) {

	if i.file == nil {
		return 0, fmt.Errorf("File not currently opened.")
	}

	return i.file.Seek(io.SeekStart, 0)
}

func (i *IOnodeFile) PidNsInode() (domain.Inode, error) {

	pid, err := strconv.Atoi(i.path)
	if err != nil {
		return 0, err
	}

	pidnsPath := strings.Join([]string{
		"/proc",
		strconv.FormatUint(uint64(pid), 10),
		"ns/pid"}, "/")

	// Extract pid-ns info from FS.
	info, err := AppFs.Stat(pidnsPath)
	if err != nil {
		logrus.Error("No process file found for pid:", pid)
		return 0, err
	}

	// In unit-testing scenarios we will extract the pidInode value from the
	// file content itself. This is a direct consequence of afero-fs lacking
	// Sys() api support.
	_, ok := AppFs.(*afero.MemMapFs)
	if ok {
		content, err := afero.ReadFile(AppFs, pidnsPath)
		if err != nil {
			return 0, err
		}
		pidInode, err := strconv.ParseUint(string(content), 10, 64)

		return pidInode, nil
	}

	// In the regular case obtain the real inode value exposed by Sys() api.
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		logrus.Error("Not a syscall.Stat_t")
		return 0, nil
	}

	return stat.Ino, nil
}

func (i *IOnodeFile) Name() string {
	return i.name
}

func (i *IOnodeFile) Path() string {
	return i.path
}

func (i *IOnodeFile) OpenFlags() int {
	return i.flags
}

func (i *IOnodeFile) SetOpenFlags(flags int) {
	i.flags = flags
}
