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
	usernsTable map[domain.Inode][]*container

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
		usernsTable: make(map[domain.Inode][]*container),
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

func (css *containerStateService) ContainerPreRegister(id, userns string) error {
	var stateCntr *container

	if userns == "" {
		logrus.Debugf("Container pre-registration started: id = %s", id)
	} else {
		logrus.Debugf("Container pre-registration started: id = %s, userns = %s", id, userns)
	}

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

	// If this container is entering an existing user-ns, record this
	if userns != "" {

		// Get the inode for the given userns
		fnode := css.ios.NewIOnode("", userns, 0)
		usernsInode, err := fnode.GetNsInode()
		if err != nil {
			css.Unlock()
			logrus.Errorf("Container pre-registration error: container %s has invalid user-ns: %s",
				cntr.id, err)
			return grpcStatus.Errorf(
				grpcCodes.NotFound,
				"Container %s missing valid userns inode",
				cntr.id,
			)
		}

		cntr.usernsInode = usernsInode

		// Update the usernsTable with this container's info
		cntrSameUserns, ok := css.usernsTable[usernsInode]
		if ok {
			cntrSameUserns = append(cntrSameUserns, cntr)
			css.usernsTable[usernsInode] = cntrSameUserns
			stateCntr = cntrSameUserns[0]
		} else {
			css.usernsTable[usernsInode] = []*container{cntr}
		}
	}

	css.idTable[cntr.id] = cntr

	// Create dedicated fuse-server for each sys container.
	//
	// Note: for sys containers that share a user-ns (e.g., for K8s + sysbox
	// pods), each sys container has a dedicated fuse-server. However, all
	// fuse-servers are given the same container state object (the container
	// struct associated with the first container in the user-ns).
	//
	// This means that all containers sharing a user-ns will share the state for
	// resources in procfs and sysfs emulated by sysbox-fs (e.g., in a K8s pod, all
	// Sysbox containers share the same /proc/uptime).
	//
	// Note that even if the first container is destroyed, a reference to its
	// container state object will be held by the fuse servers associated with
	// the other containers in the same user-ns. Therefore those will continue to
	// operate properly. Only when all containers sharing the user-ns are
	// destroyed will the container state object be garbage collected.

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

	if userns == "" {
		logrus.Debugf("Container pre-registration completed: id = %s", id)
	} else {
		logrus.Debugf("Container pre-registration completed: id = %s, userns = %s", id, userns)
	}

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

	// If we don't yet have the userns info for the container's init process
	// (i.e., we didn't receive it during pre-registration), get it now.
	if currCntr.usernsInode == 0 {
		usernsInode, err := currCntr.InitProc().UserNsInode()
		if err != nil {
			css.Unlock()
			logrus.Errorf("Container registration error: container %s has invalid user-ns: %s",
				formatter.ContainerID{cntr.id}, err)
			return grpcStatus.Errorf(
				grpcCodes.NotFound,
				"Container %s missing valid userns inode",
				cntr.id,
			)
		}
		currCntr.usernsInode = usernsInode
	}

	// If the usernsTable has no info about this container's userns, add it now.
	if _, ok := css.usernsTable[currCntr.usernsInode]; !ok {
		css.usernsTable[currCntr.usernsInode] = []*container{currCntr}
	}

	css.Unlock()

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

	// Find all containers sharing the same userns
	cntrSameUserns, ok := css.usernsTable[cntr.usernsInode]
	if !ok {
		css.Unlock()
		logrus.Errorf("Container unregistration error: could not find userns-inode in usernsTable for container %s",
			formatter.ContainerID{cntr.id})
		return grpcStatus.Errorf(
			grpcCodes.NotFound,
			"Container %s missing userns inode",
			cntr.id,
		)
	}

	// Remove the unregistered container from the list of containers sharing the userns.
	newCntrSameUserns := []*container{}
	for _, c := range cntrSameUserns {
		if c.id == cntr.id {
			continue
		}
		newCntrSameUserns = append(newCntrSameUserns, c)
	}

	if len(newCntrSameUserns) > 0 {
		css.usernsTable[cntr.usernsInode] = newCntrSameUserns
	} else {
		delete(css.usernsTable, cntr.usernsInode)
	}

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
