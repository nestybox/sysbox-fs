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

package state

import (
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	grpcCodes "google.golang.org/grpc/codes"
	grpcStatus "google.golang.org/grpc/status"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-libs/formatter"
)

type containerStateService struct {
	sync.RWMutex

	// Map to store the association between container ids (string) and its
	// corresponding container data structure.
	idTable map[string]*container

	// Map to keep track of containers sharing the same net-ns.
	netnsTable map[domain.Inode][]*container

	// Pointer to the fuse-server service engine.
	fss domain.FuseServerServiceIface

	// Pointer to the service providing process-handling capabilities.
	prs domain.ProcessServiceIface

	// Pointer to the service providing file-system I/O capabilities.
	ios domain.IOServiceIface

	// Pointer to the service providing mount helper/parser capabilities.
	mts domain.MountServiceIface
}

func NewContainerStateService() domain.ContainerStateServiceIface {

	newCss := &containerStateService{
		idTable:    make(map[string]*container),
		netnsTable: make(map[domain.Inode][]*container),
	}

	return newCss
}

func (css *containerStateService) Setup(
	fss domain.FuseServerServiceIface,
	prs domain.ProcessServiceIface,
	ios domain.IOServiceIface,
	mts domain.MountServiceIface) {

	css.fss = fss
	css.prs = prs
	css.ios = ios
	css.mts = mts
}

func (css *containerStateService) ContainerCreate(
	id string,
	initPid uint32,
	ctime time.Time,
	uidFirst uint32,
	uidSize uint32,
	gidFirst uint32,
	gidSize uint32,
	procRoPaths []string,
	procMaskPaths []string,
	service domain.ContainerStateServiceIface,
) domain.ContainerIface {

	return newContainer(
		id,
		initPid,
		ctime,
		uidFirst,
		uidSize,
		gidFirst,
		gidSize,
		procRoPaths,
		procMaskPaths,
		css,
	)
}

func (css *containerStateService) ContainerPreRegister(id, netns string) error {
	var stateCntr *container

	logrus.Debugf("Container pre-registration started: id = %s",
		formatter.ContainerID{id})

	css.Lock()

	// Ensure that new container's id is not already present.
	if _, ok := css.idTable[id]; ok {
		css.Unlock()
		logrus.Errorf("Container pre-registration error: container %s already present",
			formatter.ContainerID{id})
		return grpcStatus.Errorf(
			grpcCodes.AlreadyExists,
			"Container %s already pre-registered",
			id,
		)
	}

	cntr := &container{
		id:      id,
		service: css,
	}

	stateCntr = cntr

	// Track sharing of the container's net-ns
	cntrSameNetns := []*container{}

	if netns != "" {
		var err error
		cntrSameNetns, err = css.trackNetns(cntr, netns)
		if err != nil {
			css.Unlock()
			logrus.Errorf("Container pre-registration error: %s has invalid net-ns: %s",
				formatter.ContainerID{cntr.id}, err)
			return grpcStatus.Errorf(grpcCodes.NotFound, err.Error(), cntr.id)
		}
	}

	css.idTable[cntr.id] = cntr

	// Create a dedicated fuse-server for each sys container.
	//
	// Each sys container has a dedicated fuse-server. However, for sys
	// containers that share the same net-ns (e.g., for K8s + sysbox pods), the
	// fuse-servers for each are passed the same container state object (the
	// container struct associated with the first container in the net-ns).
	//
	// This means that all containers sharing the same net-ns will share the
	// state for resources in the container's procfs and sysfs emulated by
	// sysbox-fs (e.g., in a K8s + Sysbox pod, all containers see the same
	// /proc/uptime).
	//
	// Note that sharing a net-ns implies sharing a user-ns, because the net-ns
	// is "owned" by it's associated user-ns (see user_namespaces (7)).
	//
	// Design detail: when multiple containers share sysbox-fs emulation state,
	// even if the first container is destroyed, a reference to its container
	// state object will be held by the fuse servers associated with the other
	// containers sharing the fuse state. Therefore those will continue to
	// operate properly. Only when all containers sharing the same fuse state are
	// destroyed will the container state object be garbage collected.

	if len(cntrSameNetns) > 1 {
		stateCntr = cntrSameNetns[0]
		logrus.Debugf("Container %s will share sysbox-fs state with %v",
			formatter.ContainerID{id}, cntrSameNetns)
	}

	err := css.fss.CreateFuseServer(cntr, stateCntr)
	if err != nil {
		css.Unlock()
		logrus.Errorf("Container pre-registration error: unable to initialize fuseServer for container %s: %s",
			formatter.ContainerID{id}, err)
		return grpcStatus.Errorf(
			grpcCodes.Internal,
			"Initialization error for container-id %s",
			id,
		)
	}

	css.Unlock()

	logrus.Infof("Container pre-registration completed: id = %s",
		formatter.ContainerID{id})

	return nil
}

func (css *containerStateService) ContainerRegister(c domain.ContainerIface) error {

	cntr := c.(*container)

	logrus.Debugf("Container registration started: id = %s",
		formatter.ContainerID{cntr.id})

	css.Lock()

	// Ensure that container's id is already present (preregistration completed).
	currCntr, ok := css.idTable[cntr.id]
	if !ok {
		css.Unlock()
		logrus.Errorf("Container registration error: container %s not present",
			formatter.ContainerID{cntr.id})
		return grpcStatus.Errorf(
			grpcCodes.NotFound,
			"Container %s not found",
			cntr.id,
		)
	}

	// Update existing container with received attributes.
	if err := currCntr.update(cntr); err != nil {
		css.Unlock()
		logrus.Errorf("Container registration error: container %s not updated",
			formatter.ContainerID{cntr.id})
		return grpcStatus.Errorf(
			grpcCodes.Internal,
			"Container %s not updated",
			cntr.id,
		)
	}

	// In case we don't yet have the netns info for the container's
	// init process (e.g., we didn't receive it during pre-registration because
	// the container is not in a pod), get it now.
	if _, err := css.trackNetns(currCntr, ""); err != nil {
		css.Unlock()
		logrus.Errorf("Container registration error: %s has invalid net-ns: %s",
			formatter.ContainerID{cntr.id}, err)
		return grpcStatus.Errorf(grpcCodes.NotFound, err.Error(), cntr.id)
	}

	// Let the associated fuse-server know about the sys-container's registration
	// being completed.
	if err := css.fss.FuseServerCntrRegComplete(cntr); err != nil {
		logrus.Errorf("Container registration error: container %s not present",
			formatter.ContainerID{cntr.id})
		return grpcStatus.Errorf(grpcCodes.NotFound, err.Error(), cntr.id)
	}

	currCntr.SetRegistrationCompleted()

	css.Unlock()

	logrus.Infof("Container registration completed: %v", cntr.string())
	return nil
}

func (css *containerStateService) ContainerUpdate(c domain.ContainerIface) error {

	cntr := c.(*container)

	logrus.Debugf("Container update started: id = %s",
		formatter.ContainerID{cntr.id})

	css.Lock()

	// Identify the container being updated.
	currCntr, ok := css.idTable[cntr.id]
	if !ok {
		css.Unlock()
		logrus.Errorf("Container update failure: container %v not found",
			formatter.ContainerID{cntr.id})
		return grpcStatus.Errorf(
			grpcCodes.NotFound,
			"Container %s not found",
			cntr.id,
		)
	}

	// Update the existing container-state struct with the one being received.
	// Only 'creation-time' attribute is supported for now.
	currCntr.SetCtime(cntr.ctime)
	css.Unlock()

	logrus.Debugf("Container update completed: id = %s",
		formatter.ContainerID{cntr.id})

	return nil
}

func (css *containerStateService) ContainerUnregister(c domain.ContainerIface) error {

	cntr := c.(*container)

	logrus.Debugf("Container unregistration started: id = %s",
		formatter.ContainerID{cntr.id})

	css.Lock()

	// Ensure that container's id is already present
	_, ok := css.idTable[cntr.id]
	if !ok {
		css.Unlock()
		logrus.Errorf("Container unregistration error: container %s not present",
			cntr.id)
		return grpcStatus.Errorf(
			grpcCodes.NotFound,
			"Container %s not found",
			cntr.id,
		)
	}

	// Close the container's initPidFd.
	if cntr.initPidFd != 0 {
		unix.Close(int(cntr.InitPidFd()))
	}

	// Remove the net-ns tracking info for the unregistered container.
	//
	// Note: we don't do error checking because this can fail if the netns is not
	// yet tracked for the container (e.g., if a container is pre-registered and
	// then unregistered because the container failed to start for some reason).
	css.untrackNetns(cntr)

	// Destroy the fuse server for the container
	err := css.fss.DestroyFuseServer(cntr.id)
	if err != nil {
		css.Unlock()
		logrus.Errorf("Container unregistration error: unable to destroy fuseServer for container %s",
			cntr.id)
		return grpcStatus.Errorf(
			grpcCodes.Internal,
			"Container %s unable to destroy associated fuse-server",
			cntr.id,
		)
	}

	delete(css.idTable, cntr.id)
	css.Unlock()

	logrus.Infof("Container unregistration completed: id = %s",
		formatter.ContainerID{cntr.id})

	return nil
}

func (css *containerStateService) ContainerLookupById(id string) domain.ContainerIface {
	css.RLock()
	defer css.RUnlock()

	cntr, ok := css.idTable[id]
	if !ok {
		return nil
	}

	return cntr
}

func (css *containerStateService) FuseServerService() domain.FuseServerServiceIface {
	return css.fss
}

func (css *containerStateService) ProcessService() domain.ProcessServiceIface {
	return css.prs
}

func (css *containerStateService) MountService() domain.MountServiceIface {
	return css.mts
}

func (css *containerStateService) ContainerDBSize() int {
	css.RLock()
	defer css.RUnlock()

	return len(css.idTable)
}

// trackNetns keeps track of the container's network namespace.
func (css *containerStateService) trackNetns(cntr *container, netns string) ([]*container, error) {

	var (
		cntrSameNetns []*container
		netnsInode    uint64
		err           error
		ok            bool
	)

	if cntr.netnsInode == 0 {

		if netns != "" {
			fnode := css.ios.NewIOnode("", netns, 0)
			netnsInode, err = fnode.GetNsInode()
			if err != nil {
				return nil, fmt.Errorf("Error getting netns inode: %v", err)
			}
		} else {
			netnsInode, err = cntr.InitProc().NetNsInode()
			if err != nil {
				return nil, fmt.Errorf("Error getting netns inode: %v", err)
			}
		}

		cntr.netnsInode = netnsInode

		// Update the netnsTable with this container's info
		cntrSameNetns, ok = css.netnsTable[netnsInode]
		if ok {
			cntrSameNetns = append(cntrSameNetns, cntr)
		} else {
			cntrSameNetns = []*container{cntr}
		}
		css.netnsTable[netnsInode] = cntrSameNetns
	}

	return cntrSameNetns, nil
}

// untrackNetns removes tracking info for the given container's net-namespace.
func (css *containerStateService) untrackNetns(cntr *container) error {

	// Find all containers sharing the same netns.
	cntrSameNetns, ok := css.netnsTable[cntr.netnsInode]
	if !ok {
		return fmt.Errorf("could not find entry in netnsTable for container %s", cntr.id)
	}

	// Remove the unregistered container from the list of containers sharing the netns.
	newCntrSameNetns := []*container{}
	for _, c := range cntrSameNetns {
		if c.id == cntr.id {
			continue
		}
		newCntrSameNetns = append(newCntrSameNetns, c)
	}

	if len(newCntrSameNetns) > 0 {
		css.netnsTable[cntr.netnsInode] = newCntrSameNetns
	} else {
		delete(css.netnsTable, cntr.netnsInode)
	}

	return nil
}
