package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
	"github.com/nestybox/sysvisor/sysvisor-protobuf/sysvisorGrpc"
)

var sysfs *sysvisorFS

//
// sysvisorFS struct
//
type sysvisorFS struct {
	//
	// Top-most root directory of syvisor's emulated file-system. In our case,
	// it refers to the true root ("/") dir, as we are emulating both /proc and
	// /sys resources.
	//
	root *Dir

	//
	// File-system path associated to the root directory, "/" in sysvisor-fs
	// case.
	path string

	// Number of FS nodes being created. Not utilized at the moment.
	size int64

	//
	// Map to store the handler routines associated to all the sysvisor-fs'
	// emulated resources.
	//
	handlerMap handlerMap

	//
	// Map utilized to track the association between pid-namespaces, represented
	// by an inode, and its corresponding container structure.
	//
	pidContainerMap pidContainerMap

	//
	// Holds a one-to-one mapping between container-IDs and its associated pid-ns
	// inode.
	//
	containerInodeMap containerInodeMap

	//
	// Utilized as sysvisor-fs' ipc pipeline to enable communication with external
	// entities (i.e sysvisor-runc).
	//
	grpcServer sysvisorGrpc.Server
}

//
// newSysvisorFS constructor
//
func newSysvisorFS(path string) *sysvisorFS {

	info, err := os.Stat(path)
	if err != nil {
		fmt.Println("File-System path \"", path, "\" not found")
		return nil
	}

	newfs := &sysvisorFS{
		path: path,
		root: nil,
		size: 0,
	}

	// Creating a first node corresponding to the root element in
	// sysvisorFS.
	attr := StatToAttr(info.Sys().(*syscall.Stat_t))
	attr.Mode = os.ModeDir | os.FileMode(int(0777))
	newfs.root = NewDir(path, &attr)

	newfs.handlerMap = *newHandlerMap()
	newfs.containerInodeMap = *newContainerInodeMap()

	// TODO: Improve consistency here. 'newfs' requirement is lame, this
	// parameter shouldn't be needed, it's only purpose is to allow UTs to
	// successfully execute (see notes about sysfs utilization in pid_test.go).
	newfs.pidContainerMap = *newPidContainerMap(newfs)

	// Instantiate a grpcServer for inter-process communication.
	newfs.grpcServer = *sysvisorGrpc.NewServer(
		newfs,
		&sysvisorGrpc.CallbacksMap{
			sysvisorGrpc.ContainerRegisterMessage:   containerRegister,
			sysvisorGrpc.ContainerUnregisterMessage: containerUnregister,
			sysvisorGrpc.ContainerUpdateMessage:     containerUpdate,
		},
	)

	// Initialize sysvisorfs' gRPC server in a separate goroutine.
	go newfs.grpcServer.Init()

	return newfs
}

//
// Root method. This is a FUSE-lib requirement. Function returns sysvisor-fs'
// root-node.
//
func (fs *sysvisorFS) Root() (fs.Node, error) {
	return fs.root, nil
}

//
// TODO-1: Think about moving the following routines to a more appropiate location.
// TODO-2: There's too much code-duplication here. Refactor.
//

func containerRegister(client interface{}, data *sysvisorGrpc.ContainerData) error {

	if data == nil {
		return errors.New("Invalid input parameters")
	}

	cs, err := newContainerState(
		data.Id,
		uint32(data.InitPid),
		data.Hostname,
		data.Ctime,
		uint32(data.UidFirst),
		uint32(data.UidSize),
		uint32(data.GidFirst),
		uint32(data.GidSize),
	)
	if err != nil {
		return err
	}

	fs := client.(*sysvisorFS)
	err = fs.pidContainerMap.register(cs)
	if err != nil {
		return err
	}

	return nil
}

func containerUnregister(client interface{}, data *sysvisorGrpc.ContainerData) error {

	if data == nil {
		return errors.New("Invalid input parameters")
	}

	cs, err := newContainerState(
		data.Id,
		uint32(data.InitPid),
		data.Hostname,
		data.Ctime,
		uint32(data.UidFirst),
		uint32(data.UidSize),
		uint32(data.GidFirst),
		uint32(data.GidSize),
	)
	if err != nil {
		return err
	}

	fs := client.(*sysvisorFS)
	err = fs.pidContainerMap.unregister(cs)
	if err != nil {
		return err
	}

	return nil
}

func containerUpdate(client interface{}, data *sysvisorGrpc.ContainerData) error {

	if data == nil {
		return errors.New("Invalid input parameters")
	}

	cs, err := newContainerState(
		data.Id,
		uint32(data.InitPid),
		data.Hostname,
		data.Ctime,
		uint32(data.UidFirst),
		uint32(data.UidSize),
		uint32(data.GidFirst),
		uint32(data.GidSize),
	)
	if err != nil {
		return err
	}

	fs := client.(*sysvisorFS)
	err = fs.pidContainerMap.update(cs)
	if err != nil {
		return err
	}

	return nil
}

//
// StatToAttr helper function to translate FS node-parameters from unix/kernel
// format to FUSE ones.
//
// Kernel FS node attribs:  fuse.attr (fuse_kernel*.go)
// FUSE node attribs:       fuse.Attr (fuse.go)
//
// TODO: Place me in a more appropiate location
//
func StatToAttr(s *syscall.Stat_t) fuse.Attr {

	var a fuse.Attr

	a.Inode = uint64(s.Ino)
	a.Size = uint64(s.Size)
	a.Blocks = uint64(s.Blocks)

	a.Atime = time.Unix(s.Atim.Sec, s.Atim.Nsec)
	a.Mtime = time.Unix(s.Mtim.Sec, s.Mtim.Nsec)
	a.Ctime = time.Unix(s.Ctim.Sec, s.Ctim.Nsec)

	a.Mode = os.FileMode(s.Mode)
	a.Nlink = uint32(s.Nlink)
	a.Uid = uint32(s.Uid)
	a.Gid = uint32(s.Gid)
	a.Rdev = uint32(s.Rdev)
	a.BlockSize = uint32(s.Blksize)

	return a
}
