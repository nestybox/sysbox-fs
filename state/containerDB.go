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
	"sync"
	"time"

	"github.com/sirupsen/logrus"
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

	// Map to keep track of the association between container's user-namespaces
	// (inode) and its corresponding container data structure.
	usernsTable map[domain.Inode]*container

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
		idTable:     make(map[string]*container),
		usernsTable: make(map[domain.Inode]*container),
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

func (css *containerStateService) ContainerPreRegister(id string) error {

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
	css.idTable[cntr.id] = cntr

	// Create dedicated fuse-server for each sys container.
	err := css.fss.CreateFuseServer(cntr)
	if err != nil {
		css.Unlock()
		logrus.Errorf("Container pre-registration error: unable to initialize fuseServer for container %s",
			formatter.ContainerID{id})
		return grpcStatus.Errorf(
			grpcCodes.Internal,
			"Initialization error for container-id %s",
			id,
		)
	}

	css.Unlock()

	logrus.Debugf("Container pre-registration completed: id = %s",
		formatter.ContainerID{id})

	return nil
}

func (css *containerStateService) ContainerRegister(c domain.ContainerIface) error {

	cntr := c.(*container)

	logrus.Debugf("Container registration started: id = %s",
		formatter.ContainerID{cntr.id})

	css.Lock()

	// Ensure that container's id is already present (pregistration completed).
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

	usernsInode, err := currCntr.InitProc().UserNsInode()
	if err != nil {
		logrus.Errorf("Container registration error: container %s with invalid user-ns",
			formatter.ContainerID{cntr.id})
		return grpcStatus.Errorf(
			grpcCodes.NotFound,
			"Container %s missing valid userns inode",
			cntr.id,
		)
	}

	// Ensure that new container's init process userns inode is not already
	// registered.
	if _, ok := css.usernsTable[usernsInode]; ok {
		css.Unlock()
		logrus.Errorf("Container addition error: container %s with userns-inode %d already present",
			formatter.ContainerID{cntr.id}, usernsInode)
		return grpcStatus.Errorf(
			grpcCodes.AlreadyExists,
			"Container %s with userns inode already present",
			cntr.id,
		)
	}

	css.usernsTable[usernsInode] = currCntr
	css.Unlock()

	// No need to allocate cntr's locks as we're printing the temporary one.
	logrus.Infof("Container registration completed: %v", cntr.string())

	return nil
}

func (css *containerStateService) ContainerUpdate(c domain.ContainerIface) error {

	cntr := c.(*container)

	logrus.Debugf("Container update started: id = %s",
		formatter.ContainerID{cntr.id})

	css.Lock()

	// Identify the inode associated to the user-ns of the container being
	// updated.
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

	// Identify the inode associated to the user-ns of the container being
	// eliminated.
	currCntrIdTable, ok := css.idTable[cntr.id]
	if !ok {
		css.Unlock()
		logrus.Errorf("Container unregistration failure: container %s not found ",
			formatter.ContainerID{cntr.id})
		return grpcStatus.Errorf(
			grpcCodes.NotFound,
			"Container %s not found",
			cntr.id,
		)
	}

	usernsInode, err := cntr.InitProc().UserNsInode()
	if err != nil {
		logrus.Errorf("Container unregistration error: could not find userns-inode for container %s",
			formatter.ContainerID{cntr.id})
		return grpcStatus.Errorf(
			grpcCodes.NotFound,
			"Container %s missing userns inode",
			cntr.id,
		)
	}
	currCntrUsernsTable, ok := css.usernsTable[usernsInode]
	if !ok {
		css.Unlock()
		logrus.Errorf("Container unregistration error: could not find userns-inode %d for container %s",
			usernsInode, formatter.ContainerID{cntr.id})
		return grpcStatus.Errorf(
			grpcCodes.NotFound,
			"Container %s missing valid userns inode",
			cntr.id,
		)
	}

	if currCntrIdTable != currCntrUsernsTable {
		css.Unlock()
		logrus.Errorf("Container unregistration error: inconsistent usernsTable entry for container %s",
			formatter.ContainerID{cntr.id})
		return grpcStatus.Errorf(
			grpcCodes.Internal,
			"Container %s with corrupted information",
			cntr.id,
		)
	}

	// Destroy fuse-server associated to this sys container.
	err = css.fss.DestroyFuseServer(cntr.id)
	if err != nil {
		css.Unlock()
		logrus.Errorf("Container unregistration error: unable to destroy fuseServer for container %s",
			formatter.ContainerID{cntr.id})
		return grpcStatus.Errorf(
			grpcCodes.Internal,
			"Container %s unable to destroy associated fuse-server",
			cntr.id,
		)
	}

	delete(css.idTable, cntr.id)
	delete(css.usernsTable, usernsInode)
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

func (css *containerStateService) ContainerLookupByInode(
	usernsInode domain.Inode) domain.ContainerIface {

	css.RLock()
	defer css.RUnlock()

	cntr, ok := css.usernsTable[usernsInode]
	if !ok {
		return nil
	}

	// Although not strictly needed, let's check in container's idTable too for
	// data-consistency's sake.
	cntrIdTable, ok := css.idTable[cntr.id]
	if !ok {
		return nil
	}

	if cntr != cntrIdTable {
		return nil
	}

	return cntr
}

func (css *containerStateService) ContainerLookupByProcess(
	p domain.ProcessIface) domain.ContainerIface {

	// Identify the userNsInode corresponding to this process.
	usernsInode, err := p.UserNsInode()
	if err != nil {
		logrus.Errorf("Could not find a user-namespace for pid %d", p.Pid())
		return nil
	}

	// Find the container-state corresponding to the container hosting this
	// user-ns-inode.
	cntr := css.ContainerLookupByInode(usernsInode)
	if cntr == nil {
		// If no container is found then determine if we are dealing with a nested
		// container scenario. If that's the case, it's natural to expect sysbox-fs
		// to be totally unaware of L2 containers launching this request, so we
		// would be tempted to discard it. To avoid that we obtain the parent user
		// namespace (and its associated inode), and we search through containerDB
		// once again. If there's a match then we serve this request making use of
		// the parent (L1) system container state.
		parentUsernsInode, err := p.UserNsInodeParent()
		if err != nil {
			logrus.Errorf("Could not identify a parent user-namespace for pid %d",
				p.Pid())
			return nil
		}

		parentCntr := css.ContainerLookupByInode(parentUsernsInode)
		if parentCntr == nil {
			logrus.Infof("Could not find the container originating this request (userNsInode %d)",
				usernsInode)
			return nil
		}

		return parentCntr
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
