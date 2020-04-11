//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

package fuse

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/nestybox/sysbox-fs/domain"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
	"github.com/sirupsen/logrus"
)

// Default dentry-cache-timeout interval (in minutes). This is the maximum
// amount of time that VFS will hold on to dentry elements before starting
// to forward lookup() operations to FUSE server.
var DentryCacheTimeout = 5

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

	// Upon arrival of lookup() request we must construct a temporary ionode
	// that reflects the path of the element that needs to be looked up.
	newIOnode := d.server.service.ios.NewIOnode(req.Name, path, 0)

	// Lookup the associated handler within handler-DB.
	handler, ok := d.server.service.hds.LookupHandler(newIOnode)
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
	info, err := handler.Lookup(newIOnode, request)
	if err != nil {
		return nil, fuse.ENOENT
	}

	// Extract received file attributes and create a new element within
	// sysbox file-system.
	attr := statToAttr(info.Sys().(*syscall.Stat_t))

	// Adjust response to carry the proper dentry-cache-timeout value.
	resp.EntryValid = time.Duration(DentryCacheTimeout) * time.Minute

	// Override the uid & gid attributes with the root uid & gid in the requester's
	// user-ns.
	uid, gid, err := d.getUsernsRootUid(req.Pid, req.Uid, req.Gid)
	if err != nil {
		return nil, err
	}

	attr.Uid = uid
	attr.Gid = gid

	var newNode fs.Node

	if info.IsDir() {
		attr.Mode = os.ModeDir | attr.Mode
		newNode = NewDir(req.Name, path, &attr, d.File.server)
	} else {
		newNode = NewFile(req.Name, path, &attr, d.File.server)
	}

	return newNode, nil
}

//
// Open FS operation.
//
func (d *Dir) Open(
	ctx context.Context,
	req *fuse.OpenRequest,
	resp *fuse.OpenResponse) (fs.Handle, error) {

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

	path := filepath.Join(d.path, req.Name)

	// New ionode reflecting the path of the element to be created.
	newIOnode := d.server.service.ios.NewIOnode(req.Name, path, 0)
	newIOnode.SetOpenFlags(int(req.Flags))
	newIOnode.SetOpenMode(req.Mode)

	// Lookup the associated handler within handler-DB.
	handler, ok := d.server.service.hds.LookupHandler(newIOnode)
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
	err := handler.Open(newIOnode, request)
	if err != nil && err != io.EOF {
		logrus.Debugf("Open() error: %v", err)
		return nil, nil, err
	}
	resp.Flags |= fuse.OpenDirectIO

	// To satisfy Bazil FUSE lib we are expected to return a lookup-response
	// and an open-response, let's start with the lookup() one.
	info, err := handler.Lookup(newIOnode, request)
	if err != nil {
		return nil, nil, fuse.ENOENT
	}

	// Extract received file attributes.
	attr := statToAttr(info.Sys().(*syscall.Stat_t))

	// Adjust response to carry the proper dentry-cache-timeout value.
	resp.EntryValid = time.Duration(DentryCacheTimeout) * time.Minute

	var newNode fs.Node
	newNode = NewFile(req.Name, path, &attr, d.File.server)

	return newNode, newNode, nil
}

//
// ReadDirAll FS operation.
//
func (d *Dir) ReadDirAll(ctx context.Context, req *fuse.ReadRequest) ([]fuse.Dirent, error) {

	var children []fuse.Dirent

	logrus.Debugf("Requested ReadDirAll() on directory %v (req ID=%#v)", d.path, uint64(req.ID))

	// Lookup the associated handler within handler-DB.
	handler, ok := d.server.service.hds.LookupHandler(d.ionode)
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
	files, err := handler.ReadDirAll(d.ionode, request)
	if err != nil {
		logrus.Errorf("ReadDirAll() error: %v", err)
		return nil, fuse.ENOENT
	}

	for _, node := range files {
		//
		// For system's root dir ("/"), we will only take into account
		// the specific paths emulated by sysbox-fs.
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
