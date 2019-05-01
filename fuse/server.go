package fuse

import (
	"errors"
	"fmt"
	"log"
	"os"
	"syscall"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
	_ "bazil.org/fuse/fs/fstestutil"

	"github.com/nestybox/sysvisor/sysvisor-fs/domain"
)

type fuseService struct {
	path       string
	mountPoint string
	server     *fs.Server
	root       *Dir
	ios        domain.IOService
	hds        domain.HandlerService
}

//
//
//
func NewFuseService(
	path string,
	mountPoint string,
	ios domain.IOService,
	hds domain.HandlerService) domain.FuseService {

	// Verify the existence of the provided path in the host FS.
	info, err := os.Stat(path)
	if err != nil {
		fmt.Println("File-System path \"", path, "\" not found")
		return nil
	}

	// Creating a first node corresponding to the root element in
	// sysvisorfs.
	attr := StatToAttr(info.Sys().(*syscall.Stat_t))
	attr.Mode = os.ModeDir | os.FileMode(int(0777))

	newfs := &fuseService{
		path:       path,
		mountPoint: mountPoint,
		server:     nil,
		ios:        ios,
		hds:        hds,
		root:       nil,
	}

	//
	newfs.root = NewDir(path, path, &attr, newfs)

	return newfs
}

func (s *fuseService) Run() error {
	//
	// Creating a FUSE mount at the requested mountpoint. Notice that we are
	// making use of "allowOther" flag to allow unpriviliged users to access
	// this mount.
	//
	c, err := fuse.Mount(
		s.mountPoint,
		fuse.FSName("sysvisorfs"),
		fuse.AllowOther())
	if err != nil {
		log.Fatal(err)
		return err
	}
	defer c.Close()
	if p := c.Protocol(); !p.HasInvalidate() {
		log.Panicf("Kernel FUSE support is too old to have invalidations: version %v", p)
	}

	// Creating a FUSE server to drive kernel interactions.
	s.server = fs.New(c, nil)
	if s.server == nil {
		fmt.Println("FUSE file-system could not be created")
		return errors.New("FUSE file-system could not be created")
	}

	log.Println("Starting to serve sysvisorfs...")
	if err := s.server.Serve(s); err != nil {
		log.Panicln(err)
	}

	// Return if any error is reported by mount logic.
	<-c.Ready
	if err := c.MountError; err != nil {
		log.Fatal(err)
	}

	return nil
}

//
// Root method. This is a Bazil-FUSE-lib requirement. Function returns
// sysvisor-fs' root-node.
//
func (s *fuseService) Root() (fs.Node, error) {

	return s.root, nil
}

func (s *fuseService) MountPoint() string {

	return s.mountPoint
}

func (s *fuseService) Unmount() {

	fuse.Unmount(s.mountPoint)
}
