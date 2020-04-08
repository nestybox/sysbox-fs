//
// Copyright: (C) 2019-2020 Nestybox Inc.  All rights reserved.
//

package fuse

import (
	"os"
	"path/filepath"
	"sync"

	_ "bazil.org/fuse/fs/fstestutil"

	"github.com/nestybox/sysbox-fs/domain"
)

// FuseServerService class in charge of running/hosting sysbox-fs' FUSE Servers.
type FuseServerService struct {
	sync.RWMutex // nodeDB protection
	servers      map[string]*fuseServer
	path         string                // fs path to emulate -- "/" by default
	mountPoint   string                // base mountpoint -- "/var/lib/sysboxfs" by default
	ios          domain.IOService      // i/o service pointer
	hds          domain.HandlerService // handler service pointer
}

//
func NewFuseServerService(
	mp string,
	ios domain.IOService,
	hds domain.HandlerService) *FuseServerService {

	newServerService := &FuseServerService{
		mountPoint: mp,
		ios:        ios,
		hds:        hds,
	}

	return newServerService
}

func (fss *FuseServerService) SetContainerService(css domain.ContainerStateService) {

	fss.hds.SetStateService(css)
}

func (fss *FuseServerService) CreateFuseServer(cntrId string) domain.FuseServerIface {

	cntrMountpoint := filepath.Join(fss.mountPoint, cntrId)
	if err := os.MkdirAll(cntrMountpoint, 0600); err != nil {
		return nil
	}

	srv := &fuseServer{
		path:       "/",
		mountPoint: cntrMountpoint,
		service:    fss,
	}

	if err := srv.Init(); err != nil {
		return nil
	}

	// Initiate sysbox-fs' FUSE service.
	// if err := srv.Run(); err != nil {
	// 	logrus.Panic(err)
	// }

	go srv.Run()

	return srv
}
