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

package state

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-libs/formatter"
	libpidfd "github.com/nestybox/sysbox-libs/pidfd"
	"golang.org/x/sys/unix"
)

//
// Container type to represent all the container-state relevant to sysbox-fs.
//
type container struct {
	sync.RWMutex
	id              string                      // container-id value generated by runC
	initPid         uint32                      // initPid within container
	initPidFd       libpidfd.PidFd              //
	rootInode       uint64                      // initPid's root-path inode
	ctime           time.Time                   // container creation time
	uidFirst        uint32                      // first value of Uid range (host side)
	uidSize         uint32                      // Uid range size
	gidFirst        uint32                      // first value of Gid range (host side)
	gidSize         uint32                      // Gid range size
	regCompleted    bool                        // registration completion flag
	procRoPaths     []string                    // OCI spec read-only proc paths
	procMaskPaths   []string                    // OCI spec masked proc paths
	mountInfoParser domain.MountInfoParserIface // Per container mountinfo DB & parser
	dataStore       map[string][]byte           // Per container data store for FUSE handlers (procfs, sysfs, etc); maps fuse path to data.
	initProc        domain.ProcessIface         // container's init process
	service         *containerStateService      // backpointer to service
	intLock         sync.RWMutex                // internal lock
	extLock         sync.Mutex                  // external lock (exposed via Lock() and Unlock() methods)
	usernsInode     domain.Inode                // inode associated with the container's user namespace
	netnsInode      domain.Inode                // inode associated with the container's network namespace
}

func newContainer(
	id string,
	initPid uint32,
	ctime time.Time,
	uidFirst uint32,
	uidSize uint32,
	gidFirst uint32,
	gidSize uint32,
	procRoPaths []string,
	procMaskPaths []string,
	css *containerStateService,
) domain.ContainerIface {

	cntr := &container{
		id:            id,
		initPid:       initPid,
		ctime:         ctime,
		uidFirst:      uidFirst,
		uidSize:       uidSize,
		gidFirst:      gidFirst,
		gidSize:       gidSize,
		procRoPaths:   procRoPaths,
		procMaskPaths: procMaskPaths,
		service:       css,
	}

	return cntr
}

//
// Getters implementations.
//

func (c *container) ID() string {
	c.intLock.RLock()
	defer c.intLock.RUnlock()

	return c.id
}

func (c *container) InitPid() uint32 {
	c.intLock.RLock()
	defer c.intLock.RUnlock()

	return c.initPid
}

func (c *container) InitPidFd() libpidfd.PidFd {
	c.intLock.RLock()
	defer c.intLock.RUnlock()

	return c.initPidFd
}

func (c *container) Ctime() time.Time {
	c.intLock.RLock()
	defer c.intLock.RUnlock()

	return c.ctime
}

func (c *container) UID() uint32 {
	c.intLock.RLock()
	defer c.intLock.RUnlock()

	return c.uidFirst
}

func (c *container) GID() uint32 {
	c.intLock.RLock()
	defer c.intLock.RUnlock()

	return c.gidFirst
}

func (c *container) ProcRoPaths() []string {
	c.intLock.RLock()
	defer c.intLock.RUnlock()

	return c.procRoPaths
}

func (c *container) ProcMaskPaths() []string {
	c.intLock.RLock()
	defer c.intLock.RUnlock()

	return c.procMaskPaths
}

func (c *container) InitProc() domain.ProcessIface {
	c.intLock.RLock()
	defer c.intLock.RUnlock()

	return c.initProc
}

func (c *container) IsImmutableMountID(id int) bool {
	c.intLock.RLock()
	defer c.intLock.RUnlock()

	if info := c.mountInfoParser.LookupByMountID(id); info != nil {
		return true
	}

	return false
}

// ExtractInode obtains the inode of any given resource within a sys container's
// file-system.
func (c *container) ExtractInode(path string) (domain.Inode, error) {
	return c.mountInfoParser.ExtractInode(path)
}

func (c *container) IsImmutableRoMountID(id int) bool {
	c.intLock.RLock()
	defer c.intLock.RUnlock()

	if info := c.mountInfoParser.LookupByMountID(id); info != nil {
		mh := c.service.mts.MountHelper()
		return mh.StringToFlags(info.Options)&unix.MS_RDONLY == unix.MS_RDONLY
	}

	return false
}

func (c *container) IsImmutableMountpoint(mp string) bool {
	c.intLock.RLock()
	defer c.intLock.RUnlock()

	if info := c.mountInfoParser.LookupByMountpoint(mp); info != nil {
		return true
	}

	return false
}

func (c *container) IsImmutableRoMountpoint(mp string) bool {
	c.intLock.RLock()
	defer c.intLock.RUnlock()

	if info := c.mountInfoParser.LookupByMountpoint(mp); info != nil {
		mh := c.service.mts.MountHelper()
		return mh.StringToFlags(info.Options)&unix.MS_RDONLY == unix.MS_RDONLY
	}

	return false
}

func (c *container) IsImmutableOverlapMountpoint(mp string) bool {
	c.intLock.RLock()
	defer c.intLock.RUnlock()

	info := c.mountInfoParser.LookupByMountpoint(mp)
	if info == nil {
		return false
	}

	return c.mountInfoParser.IsOverlapMount(info)
}

func (c *container) IsImmutableMount(info *domain.MountInfo) bool {
	c.intLock.RLock()
	defer c.intLock.RUnlock()

	return c.mountInfoParser.IsCloneMount(info, false)
}

func (c *container) IsImmutableRoMount(info *domain.MountInfo) bool {
	c.intLock.RLock()
	defer c.intLock.RUnlock()

	return c.mountInfoParser.IsCloneMount(info, true)
}

func (c *container) IsImmutableBindMount(info *domain.MountInfo) bool {
	c.intLock.RLock()
	defer c.intLock.RUnlock()

	return c.mountInfoParser.IsBindMount(info)
}

func (c *container) IsImmutableRoBindMount(info *domain.MountInfo) bool {
	c.intLock.RLock()
	defer c.intLock.RUnlock()

	return c.mountInfoParser.IsRoBindMount(info)
}

func (c *container) IsRegistrationCompleted() bool {
	c.intLock.RLock()
	defer c.intLock.RUnlock()
	return c.regCompleted
}

//
// Setters implementations.
//

func (c *container) update(src *container) error {
	c.intLock.Lock()
	defer c.intLock.Unlock()

	var err error

	if c.initPid != src.initPid {
		// Initialize initProc.
		c.initProc = src.service.ProcessService().ProcessCreate(
			src.initPid,
			src.uidFirst,
			src.gidFirst,
		)
		c.initPid = src.initPid
		c.rootInode = c.initProc.RootInode()

		c.initPidFd, err = libpidfd.Open(int(c.initPid), 0)
		if err != nil {
			return err
		}
	}

	if c.ctime != src.ctime {
		c.ctime = src.ctime
	}

	if c.uidFirst != src.uidFirst {
		c.uidFirst = src.uidFirst
	}

	if c.uidSize != src.uidSize {
		c.uidSize = src.uidSize
	}

	if c.gidFirst != src.gidFirst {
		c.gidFirst = src.gidFirst
	}

	if c.gidSize != src.gidSize {
		c.gidSize = src.gidSize
	}

	if c.service != src.service {
		c.service = src.service
	}

	// Unconditional malloc + copy -- think about how to optimize if no changes
	// are detected.
	c.procRoPaths = make([]string, len(src.procRoPaths))
	copy(c.procRoPaths, src.procRoPaths)
	c.procMaskPaths = make([]string, len(src.procMaskPaths))
	copy(c.procMaskPaths, src.procMaskPaths)

	return nil
}

func (c *container) InitializeMountInfo() error {
	c.intLock.Lock()
	defer c.intLock.Unlock()

	// A per-container mountInfoParser object will be created here to hold the
	// mount-state created by sysbox-runc during container initialization.
	if c.mountInfoParser == nil {
		mip, err := c.service.mts.NewMountInfoParser(c, c.initProc, true, true, true)
		if err != nil {
			return err
		}
		c.mountInfoParser = mip
	}

	return nil
}

func (c *container) IsMountInfoInitialized() bool {
	c.intLock.RLock()
	defer c.intLock.RUnlock()

	return c.mountInfoParser != nil
}

// Container's stringer method. Notice that no internal lock is being acquired
// in this method to avoid collisions (and potential deadlocks) with Container's
// public methods. In consequence, callee methods must ensure that container's
// internal (read)lock is acquired prior to invoking this method.
func (c *container) string() string {

	return fmt.Sprintf("id = %s, initPid = %d, uid:gid = %v:%v",
		formatter.ContainerID{c.id}, int(c.initPid), c.uidFirst, c.gidFirst)
}

func (c *container) SetCtime(t time.Time) {
	c.intLock.Lock()
	defer c.intLock.Unlock()

	c.ctime = t
}

func (c *container) Data(name string, offset int64, data *[]byte) (int, error) {
	var err error

	c.intLock.RLock()
	defer c.intLock.RUnlock()

	if offset < 0 {
		return 0, fmt.Errorf("invalid offset: %d", offset)
	}

	if c.dataStore == nil {
		c.dataStore = make(map[string][]byte)
	}

	currData, ok := c.dataStore[name]
	if !ok {
		return 0, io.EOF
	}

	readLen := int64(len(*data))

	// Out-of-bounds offset
	if offset >= readLen {
		return 0, io.EOF
	}

	if offset+readLen >= int64(len(currData)) {
		// Out-of-bound length (read until end)
		*data = currData[offset:]
		err = io.EOF
	} else {
		// In-bound length
		*data = currData[offset:(offset + readLen)]
	}

	return len(*data), err
}

func (c *container) SetData(name string, offset int64, data []byte) error {

	c.intLock.Lock()
	defer c.intLock.Unlock()

	if offset < 0 {
		return fmt.Errorf("invalid offset: %d", offset)
	}

	if c.dataStore == nil {
		c.dataStore = make(map[string][]byte)
	}

	currData, ok := c.dataStore[name]

	// if this is the first write, we expect offset to be 0 (we don't support
	// sparse files yet)
	if !ok {
		if offset != 0 {
			return fmt.Errorf("invalid offset: %d", offset)
		}

		tmp := make([]byte, len(data))
		copy(tmp, data)
		c.dataStore[name] = tmp

		return nil
	}

	// if this is not the first write, we expect it to either overwrite the
	// existing data (or a subset of it), or extend it contiguously.
	if offset > int64(len(currData)) {
		return fmt.Errorf("invalid offset: %d", offset)
	}

	newData := append(currData[0:offset], data...)
	c.dataStore[name] = newData

	return nil
}

func (c *container) Lock() {
	c.extLock.Lock()
}

func (c *container) Unlock() {
	c.extLock.Unlock()
}

// Exclusively utilized for unit-testing purposes.
func (c *container) SetInitProc(pid, uid, gid uint32) error {
	if c.service == nil {
		return fmt.Errorf("No css service identified")
	}

	if c.service.ProcessService() == nil {
		return fmt.Errorf("No pts service identified")
	}

	c.initProc = c.service.ProcessService().ProcessCreate(pid, uid, gid)

	return nil
}

func (c *container) SetRegistrationCompleted() {
	c.intLock.Lock()
	defer c.intLock.Unlock()
	c.regCompleted = true
}
