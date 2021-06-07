//
// Copyright 2019-2020 Nestybox, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package sysio

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"syscall"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/sirupsen/logrus"
	"github.com/spf13/afero"
)

// Ensure IOnodeFile implements IOnode's interfaces.
var _ domain.IOServiceIface = (*ioFileService)(nil)
var _ domain.IOnodeIface = (*IOnodeFile)(nil)

//
// I/O Service providing FS interaction capabilities.
//
type ioFileService struct {
	fsType domain.IOServiceType
	appFs  afero.Fs
}

func newIOFileService(fsType domain.IOServiceType) domain.IOServiceIface {

	var fs = &ioFileService{}

	if fsType == domain.IOMemFileService {
		fs.appFs = afero.NewMemMapFs()
		fs.fsType = domain.IOMemFileService
	} else {
		fs.appFs = afero.NewOsFs()
		fs.fsType = domain.IOOsFileService
	}

	return fs
}

func (s *ioFileService) NewIOnode(
	n string,
	p string,
	mode os.FileMode) domain.IOnodeIface {
	newFile := &IOnodeFile{
		name: n,
		path: p,
		mode: mode,
		fss:  s,
	}

	return newFile
}

// Eliminate all nodes from a previously created file-system. Utilized exclusively
// for unit-testing purposes (i.e. afero.MemFs).
func (s *ioFileService) RemoveAllIOnodes() error {
	if err := s.appFs.RemoveAll("/"); err != nil {
		return err
	}

	return nil
}

func (i *ioFileService) GetServiceType() domain.IOServiceType {
	return i.fsType
}

//
// IOnode class specialization for FS interaction.
//
type IOnodeFile struct {
	name  string
	path  string
	flags int
	mode  os.FileMode
	file  afero.File
	fss   *ioFileService
}

func (i *IOnodeFile) Open() error {

	file, err := i.fss.appFs.OpenFile(i.path, i.flags, i.mode)
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
	return afero.ReadDir(i.fss.appFs, i.path)
}

func (i *IOnodeFile) ReadFile() ([]byte, error) {

	var (
		content []byte
		err     error
	)

	if i.fss.fsType == domain.IOMemFileService {
		content, err = afero.ReadFile(i.fss.appFs, i.path)
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
	inFile, err := i.fss.appFs.Open(i.path)
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

func (i *IOnodeFile) WriteFile(p []byte) error {

	if i.fss.fsType == domain.IOMemFileService {
		err := afero.WriteFile(i.fss.appFs, i.path, p, 0644)
		if err != nil {
			return err
		}

		return nil
	}

	return ioutil.WriteFile(i.path, p, i.mode)
}

func (i *IOnodeFile) Mkdir() error {
	return i.fss.appFs.Mkdir(i.path, i.mode)
}

func (i *IOnodeFile) MkdirAll() error {
	return i.fss.appFs.MkdirAll(i.path, i.mode)
}

// Collects the namespace inodes of the passed /proc/pid/ns/<namespace> file.
func (i *IOnodeFile) GetNsInode() (domain.Inode, error) {

	// In unit-testing scenarios we will extract the nsInode value from the
	// file content itself. This is a direct consequence of afero-fs lacking
	// Sys() api support.
	if i.fss.fsType == domain.IOMemFileService {
		content, err := afero.ReadFile(i.fss.appFs, i.path)
		if err != nil {
			return 0, err
		}

		nsInode, err := strconv.ParseUint(string(content), 10, 64)
		if err != nil {
			return 0, err
		}

		return nsInode, nil
	}

	info, err := os.Stat(i.path)
	if err != nil {
		logrus.Errorf("No namespace file found %s", i.path)
		return 0, err
	}

	stat := info.Sys().(*syscall.Stat_t)

	return stat.Ino, nil
}

func (i *IOnodeFile) Stat() (os.FileInfo, error) {
	return i.fss.appFs.Stat(i.path)
}

func (i *IOnodeFile) SeekReset() (int64, error) {

	if i.file == nil {
		return 0, fmt.Errorf("File not currently opened.")
	}

	return i.file.Seek(io.SeekStart, 0)
}

// Eliminate a node from a previously created file-system. Utilized exclusively
// for unit-testing purposes (i.e. afero.MemFs).
func (i *IOnodeFile) Remove() error {
	if err := i.fss.appFs.Remove(i.path); err != nil {
		return err
	}

	return nil
}

// Eliminate all nodes under the path indicated by the given ionode. Utilized
// exclusively for unit-testing purposes (i.e. afero.MemFs).
func (i *IOnodeFile) RemoveAll() error {
	if err := i.fss.appFs.RemoveAll(i.path); err != nil {
		return err
	}

	return nil
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

func (i *IOnodeFile) OpenMode() os.FileMode {
	return i.mode
}

func (i *IOnodeFile) SetName(s string) {
	i.name = s
}

func (i *IOnodeFile) SetPath(s string) {
	i.path = s
}

func (i *IOnodeFile) SetOpenFlags(flags int) {
	i.flags = flags
}

func (i *IOnodeFile) SetOpenMode(mode os.FileMode) {
	i.mode = mode
}
