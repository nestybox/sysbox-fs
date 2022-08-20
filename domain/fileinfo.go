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
	"os"
	"syscall"
	"time"
)

const (
	MaxUid = 0xFFFF
	MaxGid = 0xFFFF
)

// FileInfo is sysbox-fs' implementation of os.FileInfo interface. A concrete
// type is required during serialization operations when exchanging state between
// sysbox-fs' main and its re-exec instances.
type FileInfo struct {
	Fname    string
	Fsize    int64
	Fmode    os.FileMode
	FmodTime time.Time
	FisDir   bool
	Fsys     *syscall.Stat_t
}

func (c FileInfo) Name() string {
	return c.Fname
}

func (c FileInfo) Size() int64 {
	return c.Fsize
}

func (c FileInfo) Mode() os.FileMode {
	return c.Fmode
}

func (c FileInfo) ModTime() time.Time {
	return c.FmodTime
}

func (c FileInfo) IsDir() bool {
	return c.FisDir
}

func (c FileInfo) Sys() interface{} {
	return c.Fsys
}

// Utility function to eliminate duplicates from FileInfo slice.
func FileInfoSliceUniquify(s []os.FileInfo) []os.FileInfo {
	var result = []os.FileInfo{}

	var keys = make(map[string]bool)

	for _, info := range s {
		fname := info.Name()
		if _, ok := keys[fname]; !ok {
			keys[fname] = true
			result = append(result, info)
		}
	}

	return result
}