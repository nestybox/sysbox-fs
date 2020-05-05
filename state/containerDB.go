//
// Copyright: (C) 2019-2020 Nestybox Inc.  All rights reserved.
//

package state

import (
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	grpcCodes "google.golang.org/grpc/codes"
	grpcStatus "google.golang.org/grpc/status"

	"github.com/nestybox/sysbox-fs/domain"
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
	prs domain.ProcessService

	// Pointer to the service providing file-system I/O capabilities.
	ios domain.IOService
}

func NewContainerStateService(
	fss domain.FuseServerServiceIface,
	prs domain.ProcessService,
	ios domain.IOService) domain.ContainerStateService {

	newCss := &containerStateService{
		idTable:     make(map[string]*container),
		usernsTable: make(map[domain.Inode]*container),
		fss:         fss,
		prs:         prs,
		ios:         ios,
	}

	// Set backpointer to service parent.
	newCss.fss.SetContainerService(newCss)

	return newCss
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
) domain.ContainerIface {

	newcntr := &container{
		id:            id,
		initPid:       initPid,
		ctime:         ctime,
		uidFirst:      uidFirst,
		uidSize:       uidSize,
		gidFirst:      gidFirst,
		gidSize:       gidSize,
		procRoPaths:   procRoPaths,
		procMaskPaths: procMaskPaths,
		specPaths:     make(map[string]struct{}),
		service:       css,
	}

	return newcntr
}

func (css *containerStateService) ContainerPreRegister(id string) error {
	css.Lock()

	// Ensure that new container's id is not already present.
	if _, ok := css.idTable[id]; ok {
		css.Unlock()
		logrus.Errorf("Container pre-registration error: container %s already present",
			id)
		return grpcStatus.Errorf(
			grpcCodes.AlreadyExists,
			"Container %s already pre-registered",
			id,
		)
	}

	cntr := &container{id: id}
	css.idTable[cntr.id] = cntr

	// Create dedicated fuse-server for each sys container.
	err := css.fss.CreateFuseServer(cntr)
	if err != nil {
		css.Unlock()
		logrus.Errorf("Container pre-registration error: unable to initialize fuseServer for container %s",
			id)
		return grpcStatus.Errorf(
			grpcCodes.Internal,
			"Initialization error for container-id %s",
			id,
		)
	}

	css.Unlock()

	return nil
}

func (css *containerStateService) ContainerRegister(c domain.ContainerIface) error {
	css.Lock()

	cntr := c.(*container)

	// Ensure that container's id is already present (pregistration completed).
	currCntr, ok := css.idTable[cntr.id]
	if !ok {
		css.Unlock()
		logrus.Errorf("Container registration error: container %s not present",
			cntr.id)
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
			cntr.id)
		return grpcStatus.Errorf(
			grpcCodes.Internal,
			"Container %s not updated",
			cntr.id,
		)
	}

	usernsInode := currCntr.InitProc().UserNsInode()
	if usernsInode == 0 {
		logrus.Errorf("Container registration error: container %s with invalid user-ns",
			cntr.id)
		return grpcStatus.Errorf(
			grpcCodes.NotFound,
			"Container %s missing valid userns inode",
			cntr.id,
		)
	}

	// Ensure that new container's init process userns inode is not already registered.
	if _, ok := css.usernsTable[usernsInode]; ok {
		css.Unlock()
		logrus.Errorf("Container addition error: container %s with userns-inode %s already present",
			cntr.id, usernsInode)
		return grpcStatus.Errorf(
			grpcCodes.AlreadyExists,
			"Container %s with userns inode already present",
			cntr.id,
		)
	}

	css.usernsTable[usernsInode] = currCntr
	css.Unlock()

	logrus.Info(cntr.String())

	return nil
}

func (css *containerStateService) ContainerUpdate(c domain.ContainerIface) error {
	css.Lock()

	cntr := c.(*container)

	// Identify the inode associated to the user-ns of the container being
	// updated.
	currCntr, ok := css.idTable[cntr.id]
	if !ok {
		css.Unlock()
		logrus.Errorf("Container update failure: container %v not found", cntr.id)
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

	logrus.Info(currCntr.String())

	return nil
}

func (css *containerStateService) ContainerUnregister(c domain.ContainerIface) error {
	css.Lock()

	cntr := c.(*container)

	// Identify the inode associated to the user-ns of the container being
	// eliminated.
	currCntrIdTable, ok := css.idTable[cntr.id]
	if !ok {
		css.Unlock()
		logrus.Errorf("Container unregistration failure: container %s not found ",
			cntr.id)
		return grpcStatus.Errorf(
			grpcCodes.NotFound,
			"Container %s not found",
			cntr.id,
		)
	}

	usernsInode := cntr.InitProc().UserNsInode()
	currCntrUsernsTable, ok := css.usernsTable[usernsInode]
	if !ok {
		css.Unlock()
		logrus.Errorf("Container deletion error: could not find container %s with userns-inode %s",
			cntr.id, usernsInode)
		return grpcStatus.Errorf(
			grpcCodes.NotFound,
			"Container %s missing valid userns inode",
			cntr.id,
		)
	}

	if currCntrIdTable != currCntrUsernsTable {
		css.Unlock()
		return grpcStatus.Errorf(
			grpcCodes.Internal,
			"Container %s with corrupted information",
			cntr.id,
		)
	}

	// Create dedicated fuse-server for each sys container.
	err := css.fss.DestroyFuseServer(cntr.id)
	if err != nil {
		css.Unlock()
		logrus.Errorf("Container unregistration error: unable to destroy fuseServer for container %s",
			cntr.id)
		return grpcStatus.Errorf(
			grpcCodes.Internal,
			"Container %s unable to destroy fuse-server",
			cntr.id,
		)
	}

	delete(css.idTable, cntr.id)
	delete(css.usernsTable, usernsInode)
	css.Unlock()

	logrus.Info(currCntrIdTable.String())

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

func (css *containerStateService) ContainerLookupByProcess(p domain.ProcessIface) domain.ContainerIface {

	// Identify the userNsInode corresponding to this process.
	usernsInode := p.UserNsInode()

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
			logrus.Errorf("Could not identify a parent user-namespace for pid %v",
				p.Pid())
			return nil
		}

		parentCntr := css.ContainerLookupByInode(parentUsernsInode)
		if parentCntr == nil {
			logrus.Errorf("Could not find the container originating this request (userNsInode %v)",
				usernsInode)
			return nil
		}

		return parentCntr
	}

	return cntr
}

func (css *containerStateService) ProcessService() domain.ProcessService {
	return css.prs
}

func (css *containerStateService) ContainerDBSize() int {
	css.RLock()
	defer css.RUnlock()

	return len(css.idTable)
}
