package fuse

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
)

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
func NewDir(name string, path string, attr *fuse.Attr, srv *fuseService) *Dir {

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

	log.Println("Requested Lookup for", req.Name)

	path := filepath.Join(d.path, req.Name)

	// Return right away if the resource being queried is not available.
	info, err := os.Stat(path)
	if err != nil {
		fmt.Println("No directory", path, "found in FS")
		return nil, fuse.ENOENT
	}

	if info.IsDir() {
		log.Println("Found match for directory lookup with size", info.Size())

		//
		// Obtaining FS directory attributes. Notice that directory 'mode' must
		// be explicitly defined.
		//
		attr := StatToAttr(info.Sys().(*syscall.Stat_t))
		attr.Mode = os.ModeDir | attr.Mode

		return NewDir(req.Name, path, &attr, d.File.service), nil

	}

	log.Println("Found match for file lookup with size", info.Size())

	// Obtaining FS file attributes
	attr := StatToAttr(info.Sys().(*syscall.Stat_t))

	return NewFile(req.Name, path, &attr, d.File.service), nil
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
// ReadDirAll FS operation.
//
func (d *Dir) ReadDirAll(ctx context.Context, req *fuse.ReadRequest) ([]fuse.Dirent, error) {

	var children []fuse.Dirent

	log.Println("Requested ReadDirAll on directory", d.path)

	//files, err := d.service.ios.ReadDirAllNode(d.ionode)
	// If dealing with an emulated resource, execute the associated handle.
	handler, ok := d.service.hds.LookupHandler(d.ionode)
	if !ok {
		log.Printf("No supported handler for %v resource", d.path)
		return nil, fmt.Errorf("No supported handler for %v resource", d.path)
	}

	// Identify the pidNsInode corresponding to this pid.
	tmpNode := d.service.ios.NewIOnode("", strconv.Itoa(int(req.Pid)), 0)
	pidInode, err := d.service.ios.PidNsInode(tmpNode)
	if err != nil {
		return nil, err
	}

	// Handler execution.
	files, err := handler.ReadDirAll(d.ionode, pidInode)
	if err != nil {
		log.Printf("Error while running ReadDirAll(): ", err)
		return nil, err
	}

	for _, node := range files {
		//
		// For system's root dir ("/"), we will only take into account
		// the specific paths emulated by Sysvisorfs.
		//
		if d.path == "/" {
			if node.Name() != "sys" && node.Name() != "proc" {
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
// Mkdir FS operation
//
func (d *Dir) Mkdir(ctx context.Context, req *fuse.MkdirRequest) (fs.Node, error) {

	log.Println("Requested Mkdir() for directory", req.Name)

	path := filepath.Join(d.path, req.Name)
	newDir := NewDir(req.Name, path, &fuse.Attr{}, d.File.service)

	return newDir, nil
}
