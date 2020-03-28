//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

package fuse

import (
	"errors"
	"os"
	"sync"
	"syscall"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
	_ "bazil.org/fuse/fs/fstestutil"
	"github.com/sirupsen/logrus"
	"github.com/spf13/afero"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/sysio"
)

// FuseService class in charge of running/hosting sysbox-fs' FUSE features.
type FuseService struct {
	sync.RWMutex                       // nodeDB protection
	path         string                // fs path to emulate -- "/" by default
	mountPoint   string                // mountpoint -- "/var/lib/sysboxfs" by default
	server       *fs.Server            // bazil-fuse server instance
	nodeDB       map[string]*fs.Node   // map to store all fs nodes, e.g. "/proc/uptime" -> File
	root         *Dir                  // root node of fuse fs -- "/" by default
	ios          domain.IOService      // i/o service pointer
	hds          domain.HandlerService // handler service pointer
}

//
// NewFuseService serves as sysbox-fs' fuse-server constructor.
//
func NewFuseService(
	path string,
	mountPoint string,
	ios domain.IOService,
	hds domain.HandlerService) domain.FuseService {

	// Verify the existence of the requested path in the host FS.
	pathIOnode := ios.NewIOnode(path, path, os.ModeDir)
	pathInfo, err := pathIOnode.Stat()
	if err != nil {
		if os.IsNotExist(err) {
			logrus.Errorf("File-System path not found: %v", path)
			return nil
		} else {
			logrus.Errorf("File-System path not accessible: %v", path)
			return nil
		}
	}

	// Verify the existence of the requested mountpoint in the host FS.
	mountPointIOnode := ios.NewIOnode(mountPoint, mountPoint, os.ModeDir)
	_, err = mountPointIOnode.Stat()
	if err != nil {
		if os.IsNotExist(err) {
			logrus.Errorf("File-System mountpoint not found: %v", mountPoint)
			return nil
		} else {
			logrus.Errorf("File-System mountpoint not accessible: %v", mountPoint)
			return nil
		}
	}

	// Creating a first node corresponding to the root element in
	// sysbox-fs.
	var attr fuse.Attr
	_, ok := sysio.AppFs.(*afero.OsFs)
	if ok {
		attr = statToAttr(pathInfo.Sys().(*syscall.Stat_t))
	} else {
		attr = fuse.Attr{}
	}

	attr.Mode = os.ModeDir | os.FileMode(int(0600))

	newfs := &FuseService{
		path:       path,
		mountPoint: mountPoint,
		server:     nil,
		nodeDB:     make(map[string]*fs.Node),
		ios:        ios,
		hds:        hds,
		root:       nil,
	}

	// Build sysbox-fs top-most directory (root).
	newfs.root = NewDir(path, path, &attr, newfs)

	return newfs
}

func (s *FuseService) Run() error {
	//
	// Creating a FUSE mount at the requested mountpoint.
	//
	// The "AllowOther" flag allows unprivileged users to access the resources
	// exposed on this mountpoint.
	//
	// The "DefaultPermissions" flag serves to instruct the kernel to perform
	// its own permission check, instead of deferring all permission checking
	// to sysbox-fs filesystem.
	//
	c, err := fuse.Mount(
		s.mountPoint,
		fuse.FSName("sysboxfs"),
		fuse.AllowOther(),
		fuse.DefaultPermissions(),
	)
	if err != nil {
		logrus.Fatal(err)
		return err
	}

	// Deferred routine to enforce a clean exit should an unrecoverable error is
	// ever returned from fuse-lib.
	defer func() {
		s.Unmount()
		c.Close()
	}()

	if p := c.Protocol(); !p.HasInvalidate() {
		logrus.Panic("Kernel FUSE support is too old to have invalidations: version ", p)
		return err
	}

	// Creating a FUSE server to drive kernel interactions.
	s.server = fs.New(c, nil)
	if s.server == nil {
		logrus.Panic("FUSE file-system could not be created")
		return errors.New("FUSE file-system could not be created")
	}

	logrus.Info("Initiating sysbox-fs main-loop...")
	if err := s.server.Serve(s); err != nil {
		logrus.Panic(err)
		return err
	}

	// Return if any error is reported by mount logic.
	<-c.Ready
	if err := c.MountError; err != nil {
		logrus.Panic(err)
		return err
	}

	return nil
}

//
// Root method. This is a Bazil-FUSE-lib requirement. Function returns
// sysbox-fs' root-node.
//
func (s *FuseService) Root() (fs.Node, error) {

	return s.root, nil
}

func (s *FuseService) MountPoint() string {

	return s.mountPoint
}

func (s *FuseService) Unmount() {

	fuse.Unmount(s.mountPoint)
}
