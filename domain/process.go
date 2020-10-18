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

import (
	"reflect"
)

const (
	SymlinkMax = 40
)

type AccessMode uint32

const (
	R_OK AccessMode = 0x4 // read ok
	W_OK AccessMode = 0x2 // write ok
	X_OK AccessMode = 0x1 // execute ok
)

type ProcessIface interface {
	Pid() uint32
	Uid() uint32
	Gid() uint32
	Cwd() string
	Root() string
	IsSysAdminCapabilitySet() bool
	NsInodes() (map[string]Inode, error)
	UserNsInode() (Inode, error)
	UserNsInodeParent() (Inode, error)
	CreateNsInodes(Inode) error
	PathAccess(path string, accessFlags AccessMode) error
	GetEffCaps() [2]uint32
	SetEffCaps(caps [2]uint32)
	AdjustPersonality(
		uid uint32,
		gid uint32,
		root string,
		cwd string,
		caps [2]uint32) error
}

type ProcessServiceIface interface {
	Setup(ios IOServiceIface)
	ProcessCreate(pid uint32, uid uint32, gid uint32) ProcessIface
}

// ProcessNsMatch returns true if the given processes are in the same namespaces.
func ProcessNsMatch(p1, p2 ProcessIface) bool {
	p1Inodes, p1Err := p1.NsInodes()
	p2Inodes, p2Err := p2.NsInodes()

	if p1Err != nil || p2Err != nil {
		return false
	}

	return reflect.DeepEqual(p1Inodes, p2Inodes)
}
