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
	"errors"
	"os"
	"path/filepath"
	"sync"

	_ "bazil.org/fuse/fs/fstestutil"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/sirupsen/logrus"
)

type FuseServerService struct {
	sync.RWMutex                                   // servers map protection
	path         string                            // fs path to emulate -- "/" by default
	mountPoint   string                            // base mountpoint -- "/var/lib/sysboxfs" by default
	serversMap   map[string]*fuseServer            // tracks created fuse-servers
	css          domain.ContainerStateServiceIface // containerState service pointer
	ios          domain.IOServiceIface             // i/o service pointer
	hds          domain.HandlerServiceIface        // handler service pointer
}

// FuseServerService constructor.
func NewFuseServerService() *FuseServerService {

	newServerService := &FuseServerService{
		serversMap: make(map[string]*fuseServer),
	}

	return newServerService
}

func (fss *FuseServerService) Setup(
	mp string,
	css domain.ContainerStateServiceIface,
	ios domain.IOServiceIface,
	hds domain.HandlerServiceIface) {

	fss.css = css
	fss.ios = ios
	fss.hds = hds
	fss.mountPoint = mp
}

// FuseServerService destructor.
func (fss *FuseServerService) DestroyFuseService() {

	for k, _ := range fss.serversMap {
		fss.DestroyFuseServer(k)
	}
}

// Creates new fuse-server.
func (fss *FuseServerService) CreateFuseServer(cntr domain.ContainerIface) error {

	cntrId := cntr.ID()

	// Ensure a fuse-server does not exist for this cntr.
	fss.RLock()
	if _, ok := fss.serversMap[cntrId]; ok {
		fss.RUnlock()
		logrus.Errorf("FuseServer to create is already present for container id %s",
			cntrId)
		return errors.New("FuseServer already present")
	}
	fss.RUnlock()

	// Create required mountpoint in host file-system.
	cntrMountpoint := filepath.Join(fss.mountPoint, cntrId)
	mountpointIOnode := fss.ios.NewIOnode("", cntrMountpoint, 0600)
	if err := mountpointIOnode.MkdirAll(); err != nil {
		return errors.New("FuseServer with invalid mountpoint")
	}

	srv := NewFuseServer(
		"/",
		cntrMountpoint,
		cntr,
		fss,
	)

	// Create new fuse-server.
	if err := srv.Create(); err != nil {
		return errors.New("FuseServer initialization error")
	}

	// Launch fuse-server in a separate goroutine and wait for 'ack' before
	// moving on.
	go srv.Run()
	srv.InitWait()

	// Store newly created fuse-server.
	fss.Lock()
	fss.serversMap[cntrId] = srv.(*fuseServer)
	fss.Unlock()

	return nil
}

// Destroy a fuse-server.
func (fss *FuseServerService) DestroyFuseServer(cntrId string) error {

	// Ensure fuse-server to eliminate is present.
	fss.RLock()
	srv, ok := fss.serversMap[cntrId]
	if !ok {
		fss.RUnlock()
		logrus.Errorf("FuseServer to destroy is not present for container id %s",
			cntrId)
		return nil
	}
	fss.RUnlock()

	// Destroy fuse-server.
	if err := srv.Destroy(); err != nil {
		logrus.Errorf("FuseServer to destroy could not be eliminated for container id %s",
			cntrId)
		return nil
	}

	// Remove mountpoint dir from host file-system.
	cntrMountpoint := filepath.Join(fss.mountPoint, cntrId)
	if err := os.Remove(cntrMountpoint); err != nil {
		logrus.Errorf("FuseServer mountpoint could not be eliminated for container id %s",
			cntrId)
		return nil
	}

	// Update state.
	fss.Lock()
	delete(fss.serversMap, cntrId)
	fss.Unlock()

	return nil
}
