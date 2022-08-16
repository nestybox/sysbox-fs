//
// Copyright 2019-2021 Nestybox, Inc.
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
	"path/filepath"
	"time"

	"github.com/nestybox/sysbox-fs/domain"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
	"github.com/sirupsen/logrus"
)

// Default dentry-cache-timeout interval: This is the maximum
// amount of time that VFS will hold on to dentry elements before starting
// to forward lookup() operations to FUSE server. We want to set this to
// infinite ideally; we set it to the max allowed value.
var DentryCacheTimeout int64 = 0x7fffffffffffffff

//
// Dir struct serves as a FUSE-friendly abstraction to represent directories
// present in the host FS.
//
type Dir struct {
	//
	// Underlying File struct representing each directory.
	//
	File

	//
	// TODO: Think about the need to define virtual-folders structs and its
	// associated logic. If there's no such a need, and there's no
	// differentiated logic between Dir and File structs, then consider the
	// option of consolidating all associated logic within a single
	// abstraction.
	//
}

//
// NewDir method serves as Dir constructor.
//
func NewDir(name string, path string, attr *fuse.Attr, srv *fuseServer) *Dir {

	newDir := &Dir{
		File: *NewFile(name, path, attr, srv),
	}

	return newDir
}

//
// Lookup FS operation.
//
func (d *Dir) Lookup(
	ctx context.Context,
	req *fuse.LookupRequest,
	resp *fuse.LookupResponse) (fs.Node, error) {

	logrus.Debugf("Requested Lookup() operation for entry %v (req ID=%#x)", req.Name, uint64(req.ID))

	path := filepath.Join(d.path, req.Name)

	// nodeDB caches the attributes associated with each file. This way, we perform the
	// lookup of a given procfs/sysfs dir/file only once, improving performance. This works
	// because:
	//   * there's a dedicated nodeDB (fuseServer) per sys-container
	//   * all attributes of procfs/sysfs dirs/files are static (e.g., permissions never
	//     change, and uid/gid values match those of the root user in the sys-container's
	//     user-ns as long as user-ns-nesting continue to be unsupported).
	d.server.RLock()
	node, ok := d.server.nodeDB[path]
	if ok {
		d.server.RUnlock()
		return *node, nil
	}
	d.server.RUnlock()

	// Ensure operation is generated from within a registered sys container.
	if d.server.container == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return nil, fmt.Errorf("Could not find container originating this request (pid %v)",
			req.Pid)
	}

	// Upon arrival of lookup() request we must construct a temporary ionode
	// that reflects the path of the element that needs to be looked up.
	ionode := d.server.service.ios.NewIOnode(req.Name, path, 0)

	// Lookup the associated handler within handler-DB.
	handler, ok := d.server.service.hds.LookupHandler(ionode)
	if !ok {
		logrus.Errorf("No supported handler for %v resource", d.path)
		return nil, fmt.Errorf("No supported handler for %v resource", d.path)
	}

	request := &domain.HandlerRequest{
		ID:        uint64(req.ID),
		Pid:       req.Pid,
		Uid:       req.Uid,
		Gid:       req.Gid,
		Container: d.server.container,
	}

	// Handler execution.
	info, err := handler.Lookup(ionode, request)
	if err != nil {
		return nil, fuse.ENOENT
	}

	// Convert os.FileInfo attributes to fuseAttr format.
	fuseAttrs := convertFileInfoToFuse(info)

	// Identify the root uid & gid in the requester's user-ns.
	prs := d.server.service.hds.ProcessService()
	process := prs.ProcessCreate(req.Pid, req.Uid, req.Gid)

	rootUid, rootGid, err := process.UsernsRootUidGid()
	if err != nil {
		return nil, err
	}

	// Override the uid & gid attributes with the root uid & gid in the
	// requester's user-ns if, and only if, these ones have not been
	// explicitly set to match the special maxUid/MaxGid values (refer to
	// sysKernel for details).
	if fuseAttrs.Uid != domain.MaxUid {
		fuseAttrs.Uid = rootUid
	}
	if fuseAttrs.Gid != domain.MaxGid {
		fuseAttrs.Gid = rootGid
	}

	var newNode fs.Node

	// Create a new file/dir entry associated to the received os.FileInfo.
	if info.IsDir() {
		fuseAttrs.Mode |= os.ModeDir
		newNode = NewDir(req.Name, path, &fuseAttrs, d.File.server)
	} else {
		newNode = NewFile(req.Name, path, &fuseAttrs, d.File.server)
	}

	// Insert new fs node into nodeDB.
	d.server.Lock()
	d.server.nodeDB[path] = &newNode
	d.server.Unlock()

	// Adjust response to carry the proper dentry-cache-timeout value.
	resp.EntryValid = time.Duration(DentryCacheTimeout)

	return newNode, nil
}

//
// Open FS operation.
//
func (d *Dir) Open(
	ctx context.Context,
	req *fuse.OpenRequest,
	resp *fuse.OpenResponse) (fs.Handle, error) {

	// Ensure operation is generated from within a registered sys container.
	if d.server.container == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return nil, fmt.Errorf("Could not find container originating this request (pid %v)",
			req.Pid)
	}

	_, err := d.File.Open(ctx, req, resp)
	if err != nil {
		return nil, err
	}

	return d, nil
}

//
// Create FS operation.
//
func (d *Dir) Create(
	ctx context.Context,
	req *fuse.CreateRequest,
	resp *fuse.CreateResponse) (fs.Node, fs.Handle, error) {

	logrus.Debugf("Requested Create() operation for entry %v (req ID=%#x)", req.Name, uint64(req.ID))

	// Ensure operation is generated from within a registered sys container.
	if d.server.container == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return nil, nil, fmt.Errorf("Could not find container originating this request (pid %v)",
			req.Pid)
	}

	path := filepath.Join(d.path, req.Name)

	// New ionode reflecting the path of the element to be created.
	ionode := d.server.service.ios.NewIOnode(req.Name, path, 0)
	ionode.SetOpenFlags(int(req.Flags))
	ionode.SetOpenMode(req.Mode)

	// Lookup the associated handler within handler-DB.
	handler, ok := d.server.service.hds.LookupHandler(ionode)
	if !ok {
		logrus.Errorf("No supported handler for %v resource", path)
		return nil, nil, fmt.Errorf("No supported handler for %v resource", path)
	}

	request := &domain.HandlerRequest{
		ID:        uint64(req.ID),
		Pid:       req.Pid,
		Uid:       req.Uid,
		Gid:       req.Gid,
		Container: d.server.container,
	}

	// Handler execution. 'Open' handler will create new element if requesting
	// process has the proper credentials / capabilities.
	err := handler.Open(ionode, request)
	if err != nil && err != io.EOF {
		logrus.Debugf("Open() error: %v", err)
		return nil, nil, err
	}
	resp.Flags |= fuse.OpenDirectIO

	// To satisfy Bazil FUSE lib we are expected to return a lookup-response
	// and an open-response, let's start with the lookup() one.
	info, err := handler.Lookup(ionode, request)
	if err != nil {
		return nil, nil, fuse.ENOENT
	}

	// Extract received file attributes.
	fuseAttrs := convertFileInfoToFuse(info)

	// Adjust response to carry the proper dentry-cache-timeout value.
	resp.EntryValid = time.Duration(DentryCacheTimeout)

	var newNode fs.Node
	newNode = NewFile(req.Name, path, &fuseAttrs, d.File.server)

	// Insert new fs node into nodeDB.
	d.server.Lock()
	d.server.nodeDB[path] = &newNode
	d.server.Unlock()

	return newNode, newNode, nil
}

//
// ReadDirAll FS operation.
//
func (d *Dir) ReadDirAll(ctx context.Context, req *fuse.ReadRequest) ([]fuse.Dirent, error) {

	var children []fuse.Dirent

	logrus.Debugf("Requested ReadDirAll() on directory %v (req ID=%#v)", d.path, uint64(req.ID))

	// Ensure operation is generated from within a registered sys container.
	if d.server.container == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return nil, fmt.Errorf("Could not find container originating this request (pid %v)",
			req.Pid)
	}

	// New ionode reflecting the path of the element to be created.
	ionode := d.server.service.ios.NewIOnode(d.name, d.path, 0)
	ionode.SetOpenFlags(int(req.Flags))

	// Lookup the associated handler within handler-DB.
	handler, ok := d.server.service.hds.LookupHandler(ionode)
	if !ok {
		logrus.Errorf("No supported handler for %v resource", d.path)
		return nil, fmt.Errorf("No supported handler for %v resource", d.path)
	}

	request := &domain.HandlerRequest{
		ID:        uint64(req.ID),
		Pid:       req.Pid,
		Uid:       req.Uid,
		Gid:       req.Gid,
		Container: d.server.container,
	}

	// Handler execution.
	files, err := handler.ReadDirAll(ionode, request)
	if err != nil {
		logrus.Debugf("ReadDirAll() error: %v", err)
		return nil, fuse.ENOENT
	}

	for _, node := range files {
		//
		// For ReadDirAll on the sysbox-fs root dir ("/"), we only act
		// on the subdirs emulated by sysbox-fs (e.g., /proc, /sys).
		//
		if d.path == "/" {
			if node.Name() != "sys" && node.Name() != "proc" &&
				node.Name() != "testing" {
				continue
			}
		}

		elem := fuse.Dirent{Name: node.Name()}

		if node.IsDir() {
			elem.Type = fuse.DT_Dir
		} else if node.Mode().IsRegular() {
			elem.Type = fuse.DT_File
		}

		children = append(children, elem)
	}

	return children, nil
}

//
// Mkdir FS operation.
//
func (d *Dir) Mkdir(ctx context.Context, req *fuse.MkdirRequest) (fs.Node, error) {

	logrus.Debugf("Requested Mkdir() on directory %v (Req ID=%#v)", req.Name, uint64(req.ID))

	// Ensure operation is generated from within a registered sys container.
	if d.server.container == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return nil, fmt.Errorf("Could not find container originating this request (pid %v)",
			req.Pid)
	}

	path := filepath.Join(d.path, req.Name)
	newDir := NewDir(req.Name, path, &fuse.Attr{}, d.File.server)

	return newDir, nil
}

//
// Forget FS operation.
//
func (d *Dir) Forget() {

	d.File.Forget()
}
