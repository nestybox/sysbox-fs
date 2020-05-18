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

	"github.com/nestybox/sysbox-fs/domain"
)

// FuseServer class in charge of running/hosting sysbox-fs' FUSE server features.
type fuseServer struct {
	sync.RWMutex                       // nodeDB protection
	path         string                // fs path to emulate -- "/" by default
	mountPoint   string                // mountpoint -- "/var/lib/sysboxfs" by default
	container    domain.ContainerIface // associated sys container
	server       *fs.Server            // bazil-fuse server instance
	nodeDB       map[string]*fs.Node   // map to store all fs nodes, e.g. "/proc/uptime" -> File
	root         *Dir                  // root node of fuse fs -- "/" by default
	initDone     chan bool             // sync-up channel to alert about fuse-server's init-completion
	service      *FuseServerService    // backpointer to parent service
}

func (s *fuseServer) Create() error {

	// Verify the existence of the requested path in the host FS.
	pathIOnode := s.service.ios.NewIOnode(s.path, s.path, os.ModeDir)
	pathInfo, err := pathIOnode.Stat()
	if err != nil {
		if os.IsNotExist(err) {
			logrus.Errorf("File-System path not found: %v", s.path)
			return err
		} else {
			logrus.Errorf("File-System path not accessible: %v", s.path)
			return err
		}
	}

	// Verify the existence of the requested mountpoint in the host FS.
	mountPointIOnode := s.service.ios.NewIOnode(
		s.mountPoint,
		s.mountPoint,
		os.ModeDir)
	_, err = mountPointIOnode.Stat()
	if err != nil {
		if os.IsNotExist(err) {
			logrus.Errorf("File-System mountpoint not found: %v", s.mountPoint)
			return err
		} else {
			logrus.Errorf("File-System mountpoint not accessible: %v", s.mountPoint)
			return err
		}
	}

	// Creating a first node corresponding to the root (dir) element in
	// sysbox-fs.
	var attr fuse.Attr
	if s.service.ios.GetServiceType() == domain.IOMemFileService {
		attr = fuse.Attr{}
	} else {
		attr = statToAttr(pathInfo.Sys().(*syscall.Stat_t))
	}
	attr.Mode = os.ModeDir | os.FileMode(int(0600))

	// Build sysbox-fs top-most directory (root).
	s.root = NewDir(s.path, s.path, &attr, s)

	// Initialize pending members.
	s.nodeDB = make(map[string]*fs.Node)
	s.initDone = make(chan bool)

	return nil
}

func (s *fuseServer) Run() error {
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

	// At this point we are done with fuse-server initialization, so let's
	// caller know about it.
	s.initDone <- true

	// Launch fuse-server's main-loop to handle incoming requests.
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

func (s *fuseServer) Destroy() error {

	// Unmount sysboxfs from mountpoint.
	err := fuse.Unmount(s.mountPoint)
	if err != nil {
		logrus.Errorf("FUSE file-system could not be unmounted: %v", err)
		return err
	}

	// Unset pointers for GC purposes.
	s.container = nil
	s.server = nil
	s.root = nil
	s.service = nil

	return nil
}

//
// Root method. This is a Bazil-FUSE-lib requirement. Function returns
// sysbox-fs' root-node.
//
func (s *fuseServer) Root() (fs.Node, error) {

	return s.root, nil
}

// Ensure that fuse-server initialization is completed before moving on
// with sys container's pre-registration sequence.
func (s *fuseServer) InitWait() {
	<-s.initDone
}

func (s *fuseServer) MountPoint() string {

	return s.mountPoint
}

func (s *fuseServer) Unmount() {

	fuse.Unmount(s.mountPoint)
}
