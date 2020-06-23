//
// Copyright: (C) 2019-2020 Nestybox Inc.  All rights reserved.
//

package domain

import (
	"os"
	"syscall"
	"time"
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
