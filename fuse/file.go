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

package fuse

import (
	"context"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
)

type File struct {
	// File name.
	name string

	// File absolute-path + name.
	path string

	// File attributes.
	attr *fuse.Attr

	// Skip remapping uid/gid values.
	skipIdRemap bool

	// Pointer to parent fuseService hosting this file/dir.
	server *fuseServer
}

// NewFile method serves as File constructor.
func NewFile(req *domain.HandlerRequest, attr *fuse.Attr, srv *fuseServer) *File {

	newFile := &File{
		name:        req.Name,
		path:        req.Path,
		attr:        attr,
		skipIdRemap: req.SkipIdRemap,
		server:      srv,
	}

	return newFile
}

// Attr FS operation.
func (f *File) Attr(ctx context.Context, a *fuse.Attr) error {

	logrus.Debugf("Requested Attr() operation for entry %v", f.path)

	// Simply return the attributes that were previously collected during the
	// lookup() execution.
	*a = *f.attr

	// Override the uid & gid attributes with the user-ns' root uid & gid of the
	// sys container under which the request is received. In the future we should
	// return the requester's user-ns root uid & gid instead, which could differ
	// from the sys container's one if request is originated from an L2 container.
	// Also, this will help us to support "unshare -U -m --mount-proc" inside a
	// sys container.
	//
	// Notice, that in certain cases we may want to skip this uid/gid remapping
	// process for certain nodes if its associated handler requests so.
	if a.Uid == 0 && !f.skipIdRemap {
		a.Uid = f.server.ContainerUID()
	}
	if a.Gid == 0 && !f.skipIdRemap {
		a.Gid = f.server.ContainerGID()
	}

	// As per man fuse(4), here we set the attribute's cache-duration to the
	// largest possible value to ensure getattr()s are only received once per
	// node. Notice that this behavior can be only enforced once the container
	// is fully initialized as we don't want interim node attrs (i.e., during
	// registration the container's uid/gid attrs are temporarily absent) to
	// be permanently recorded in the FUSE nodes DB. By setting this value to
	// zero during container initialization, we are slowing this process down
	// (around 1/3rd extra file-ops), but that's the price to pay to be able
	// to offer a consistent experience: users will always see the proper
	// node attrs, regardless of the timing of the incoming file-ops.
	if !f.server.IsCntrRegCompleted() {
		a.Valid = time.Duration(0)
	} else {
		a.Valid = time.Duration(AttribCacheTimeout)
	}

	logrus.Debugf("Attr() operation for entry %v: %+v", f.path, *a)

	return nil
}

// Open FS operation.
func (f *File) Open(
	ctx context.Context,
	req *fuse.OpenRequest,
	resp *fuse.OpenResponse) (fs.Handle, error) {

	logrus.Debugf("Requested Open() operation for entry %v (Req ID=%#v)",
		f.path, uint64(req.ID))

	// Ensure operation is generated from within a registered sys container.
	if f.server.container == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return nil, fmt.Errorf("Could not find container originating this request (pid %v)",
			req.Pid)
	}

	ionode := f.server.service.ios.NewIOnode(f.name, f.path, f.attr.Mode)
	ionode.SetOpenFlags(int(req.Flags))

	// Lookup the associated handler within handler-DB.
	handler, ok := f.server.service.hds.LookupHandler(ionode)
	if !ok {
		logrus.Errorf("No supported handler for %v resource", f.path)
		return nil, fmt.Errorf("No supported handler for %v resource", f.path)
	}

	handlerReq := &domain.HandlerRequest{
		ID:        uint64(req.ID),
		Pid:       req.Pid,
		Uid:       req.Uid,
		Gid:       req.Gid,
		Container: f.server.container,
	}

	// Handler execution.
	nonSeekable, err := handler.Open(ionode, handlerReq)
	if err != nil && err != io.EOF {
		logrus.Debugf("Open() error: %v", err)
		return nil, err
	}

	//
	// Due to the nature of procfs and sysfs, files lack explicit sizes (other
	// than zero) as regular files have. In consequence, read operations (also
	// writes) may not be properly handled by kernel, as these ones extend
	// beyond the file sizes reported by Attr() / GetAttr().
	//
	// A solution to this problem is to rely on O_DIRECT flag for all the
	// interactions with procfs/sysfs files. By making use of this flag,
	// sysbox-fs will ensure that it receives all read/write requests
	// generated by fuse-clients, regardless of the file-size issue mentioned
	// above. For regular files, this approach usually comes with a cost, as
	// page-cache is being bypassed for all files I/O; however, this doesn't
	// pose a problem for Sysbox as we are dealing with special FSs.
	//
	resp.Flags |= fuse.OpenDirectIO

	if nonSeekable {
		resp.Flags |= fuse.OpenNonSeekable
	}

	return f, nil
}

// Release FS operation.
func (f *File) Release(ctx context.Context, req *fuse.ReleaseRequest) error {

	logrus.Debugf("Requested Release() operation for entry %v (Req ID=%#v)",
		f.path, uint64(req.ID))

	//
	// Upon arrival of incoming fuse requests, sysbox-fs open()s and close()s
	// the associated file-system node. IOW, upon successful handling of an
	// open() fuse request, no file-system state (i.e. opened file-descriptor)
	// will be held in sysbox-fs for opened dentries. Subsequent fuse requests
	// generated by the same fuse-client process, will re-open the associated
	// file to carry out the corresponding read/write operation.
	//
	// Notice that this approach allows us to handle emulated and non-emulated
	// fs resources in the same manner. Non-emulated resources are only
	// reachable through 'nsexec' mechanisms, which relies on the utilization
	// of different processes to perform a determined i/o operation. In this
	// scenario, there's no point in open()ing and clos()ing files, as the
	// process performing the interim action (let's say, an open request) will
	// die upon completion, which will necessarily end up with the process'
	// fd-table getting wiped out by kernel upon process' exit().
	//
	// That is all to say, that there is no need to do anything with these
	// release() requests, as the associated inode is already closed by the
	// time these requests arrive. And that covers both non-emulated ('nsexec')
	// and emulated nodes.

	return nil
}

// Read FS operation.
func (f *File) Read(
	ctx context.Context,
	req *fuse.ReadRequest,
	resp *fuse.ReadResponse) error {

	logrus.Debugf("Requested Read() operation for entry %v (Req ID=%#v)",
		f.path, uint64(req.ID))

	// Ensure operation is generated from within a registered sys container.
	if f.server.container == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return fmt.Errorf("Could not find container originating this request (pid %v)",
			req.Pid)
	}

	ionode := f.server.service.ios.NewIOnode(f.name, f.path, f.attr.Mode)

	// Identify the associated handler and execute it accordingly.
	handler, ok := f.server.service.hds.LookupHandler(ionode)
	if !ok {
		logrus.Errorf("Read() error: No supported handler for %v resource", f.path)
		return fmt.Errorf("No supported handler for %v resource", f.path)
	}

	handlerReq := &domain.HandlerRequest{
		ID:        uint64(req.ID),
		Pid:       req.Pid,
		Uid:       req.Uid,
		Gid:       req.Gid,
		Offset:    req.Offset,
		Data:      make([]byte, req.Size),
		Container: f.server.container,
	}

	// Handler execution.
	n, err := handler.Read(ionode, handlerReq)
	if err != nil && err != io.EOF {
		logrus.Debugf("Read() error: %v", err)
		return err
	}

	resp.Data = handlerReq.Data[:n]
	return nil
}

// Write FS operation.
func (f *File) Write(
	ctx context.Context,
	req *fuse.WriteRequest,
	resp *fuse.WriteResponse) error {

	logrus.Debugf("Requested Write() operation for entry %v (Req ID=%#v)",
		f.path, uint64(req.ID))

	// Ensure operation is generated from within a registered sys container.
	if f.server.container == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return fmt.Errorf("Could not find container originating this request (pid %v)",
			req.Pid)
	}

	ionode := f.server.service.ios.NewIOnode(f.name, f.path, f.attr.Mode)

	// Lookup the associated handler within handler-DB.
	handler, ok := f.server.service.hds.LookupHandler(ionode)
	if !ok {
		logrus.Errorf("Write() error: No supported handler for %v resource", f.path)
		return fmt.Errorf("No supported handler for %v resource", f.path)
	}

	request := &domain.HandlerRequest{
		ID:        uint64(req.ID),
		Pid:       req.Pid,
		Uid:       req.Uid,
		Gid:       req.Gid,
		Data:      req.Data,
		Container: f.server.container,
	}

	// Handler execution.
	n, err := handler.Write(ionode, request)
	if err != nil && err != io.EOF {
		logrus.Debugf("Write() error: %v", err)
		return err
	}

	resp.Size = n
	return nil
}

func (f *File) Readlink(
	ctx context.Context,
	req *fuse.ReadlinkRequest) (string, error) {

	logrus.Debugf("Requested Readlink() operation for entry %v (Req ID=%#v)",
		f.path, uint64(req.ID))

	// Ensure operation is generated from within a registered sys container.
	if f.server.container == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)", req.Pid)
		return "", fmt.Errorf("Could not find container originating this request (pid %v)", req.Pid)
	}

	ionode := f.server.service.ios.NewIOnode(f.name, f.path, f.attr.Mode)

	// Lookup the associated handler within handler-DB.
	handler, ok := f.server.service.hds.LookupHandler(ionode)
	if !ok {
		logrus.Errorf("Readlink() error: No supported handler for %v resource", f.path)
		return "", fmt.Errorf("No supported handler for %v resource", f.path)
	}

	request := &domain.HandlerRequest{
		ID:        uint64(req.ID),
		Pid:       req.Pid,
		Uid:       req.Uid,
		Gid:       req.Gid,
		Container: f.server.container,
	}

	// Handler execution.
	link, err := handler.ReadLink(ionode, request)
	if err != nil && err != io.EOF {
		logrus.Debugf("Readlink() error: %v", err)
		return "", err
	}

	return link, nil
}

// Setattr FS operation.
func (f *File) Setattr(
	ctx context.Context,
	req *fuse.SetattrRequest,
	resp *fuse.SetattrResponse) error {

	logrus.Debugf("Requested Setattr() operation for entry %v (Req ID=%#v)",
		f.path, uint64(req.ID))

	// Ensure operation is generated from within a registered sys container.
	if f.server.container == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return fmt.Errorf("Could not find container originating this request (pid %v)",
			req.Pid)
	}

	// No file attr changes are allowed in a procfs, with the exception of
	// 'size' modifications which are needed to allow write()/truncate() ops.
	// All other 'fuse.SetattrValid' operations will be rejected.
	if req.Valid.Size() {
		return nil
	}

	return fuse.EPERM
}

// Forget FS operation.
func (f *File) Forget() {

	logrus.Debugf("Requested Forget() operation for entry %v", f.path)

	f.server.Lock()
	defer f.server.Unlock()

	if _, ok := f.server.nodeDB[f.path]; !ok {
		return
	}

	delete(f.server.nodeDB, f.path)
}

// Size method returns the 'size' of a File element.
func (f *File) Size() uint64 {
	return f.attr.Size
}

// Mode method returns the 'mode' of a File element.
func (f *File) Mode() os.FileMode {
	return f.attr.Mode
}

// ModTime method returns the modification-time of a File element.
func (f *File) ModTime() time.Time {
	return f.attr.Mtime
}

// convertFileInfoToFuse function translates FS node-attributes from a kernel
// friendly DS type, to those expected by Bazil-FUSE-lib to interact with
// FUSE-clients.
//
// Function takes as parameter the os.FileInfo object holding the attributes
// that we want to convert, and then place the converted attributes into a
// new DS which later on will be processed by Bazil FUSE-lib.
//
// For reference, the attributes' format expected by Bazil-FUSE-lib are defined
// here: bazil/fuse.go (fuse.Attr DS).
func convertFileInfoToFuse(info os.FileInfo) fuse.Attr {
	var a fuse.Attr

	// If the fileInfo does not have a stat() method (e.g., for files that are
	// virtual and not present in the host file system), translate using the
	// available file info.
	stat := info.Sys().(*syscall.Stat_t)
	if stat == nil {
		a.Size = uint64(info.Size())
		a.Mode = info.Mode()
		a.Mtime = info.ModTime()
		a.Nlink = 1
		a.BlockSize = 1024
		return a
	}

	// Otherwise, translate using the file info returned by stat(), except for
	// the file size, which is always picked up from the file info.
	a.Size = uint64(info.Size())

	a.Inode = uint64(stat.Ino)
	a.Blocks = uint64(stat.Blocks)
	a.Atime = time.Unix(int64(stat.Atim.Sec), int64(stat.Atim.Nsec))
	a.Mtime = time.Unix(int64(stat.Mtim.Sec), int64(stat.Mtim.Nsec))
	a.Ctime = time.Unix(int64(stat.Ctim.Sec), int64(stat.Ctim.Nsec))
	a.Mode = os.FileMode(stat.Mode)
	a.Nlink = uint32(stat.Nlink)
	a.Uid = uint32(stat.Uid)
	a.Gid = uint32(stat.Gid)
	a.Rdev = uint32(stat.Rdev)
	a.BlockSize = uint32(stat.Blksize)

	return a
}
