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

package domain

import "os"

type Inode = uint64 // 0 = invalid inode

//
// ioNode interface serves as an abstract-class to represent all I/O resources
// with whom sysbox-fs operates. All I/O transactions will be carried out
// through the methods exposed by this interface and its derived sub-classes.
// There are two specializations of this interface at the moment:
//
// 1. ioNodeFile: Basically, a wrapper over os.File type to allow interactions
//    with the host FS. To be utilized in production scenarios.
//
// 2. iMemFile: Utilized for unit testing.
//

type IOServiceType = int

const (
	Unknown          IOServiceType = iota
	IOOsFileService                // production / regular purposes
	IOMemFileService               // unit-testing purposes
)

type IOServiceIface interface {
	NewIOnode(n string, p string, attr os.FileMode) IOnodeIface
	RemoveAllIOnodes() error
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
	Remove() error
	RemoveAll() error
	//
	// Required getters/setters.
	//
	Name() string
	Path() string
	OpenFlags() int
	OpenMode() os.FileMode
	GetNsInode() (Inode, error)
	SetPath(s string)
	SetOpenFlags(flags int)
	SetOpenMode(mode os.FileMode)
}
