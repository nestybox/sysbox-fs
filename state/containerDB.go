//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

package state

import (
	"errors"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
)

type containerStateService struct {
	sync.RWMutex

	// Map to store the association between container ids (string) and the inode
	// corresponding to the container's pid-namespace.
	idTable map[string]domain.Inode

	// Map to keep track of the association between container's user-namespaces
	// (inode) and the internal structure to hold all the container state.
	usernsTable map[domain.Inode]*container

	// Pointer to the service providing process-handling capabilities.
	prs domain.ProcessService

	// Pointer to the service providing file-system I/O capabilities.
	ios domain.IOService
}

func NewContainerStateService(
	prs domain.ProcessService,
	ios domain.IOService) domain.ContainerStateService {

	newCSS := &containerStateService{
		idTable:     make(map[string]domain.Inode),
		usernsTable: make(map[domain.Inode]*container),
		prs:         prs,
		ios:         ios,
	}

	return newCSS
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
	}

	newcntr.specPaths = make(map[string]struct{})

	for _, v := range newcntr.procRoPaths {
		newcntr.specPaths[v] = struct{}{}
	}
	for _, v := range newcntr.procMaskPaths {
		newcntr.specPaths[v] = struct{}{}
	}

	newcntr.initProc = css.prs.ProcessCreate(initPid, uidFirst, gidFirst)

	return newcntr
}

func (css *containerStateService) ContainerAdd(c domain.ContainerIface) error {
	css.Lock()

	cntr := c.(*container)

	// Ensure that new container's id is not already present.
	if _, ok := css.idTable[cntr.id]; ok {
		css.Unlock()
		logrus.Errorf("Container addition error: container ID %v already present", cntr.id)
		return errors.New("Container ID already present")
	}

	// Ensure that new container's init process userns inode is not already registered.
	usernsInode := cntr.initProc.UserNsInode()
	if _, ok := css.usernsTable[usernsInode]; ok {
		css.Unlock()
		logrus.Errorf("Container addition error: container with userns-inode %v already present",
			usernsInode)
		return errors.New("Container with userns-inode already present")
	}

	css.idTable[cntr.id] = usernsInode
	css.usernsTable[usernsInode] = cntr
	css.Unlock()

	logrus.Info(cntr.String())

	return nil
}

func (css *containerStateService) ContainerUpdate(c domain.ContainerIface) error {
	css.Lock()

	cntr := c.(*container)

	//
	// Identify the inode associated to the user-ns of the container being
	// updated.
	//
	inode, ok := css.idTable[cntr.id]
	if !ok {
		css.Unlock()
		logrus.Errorf("Container update failure: container ID %v not found", cntr.id)
		return errors.New("Container ID not found")
	}

	// Obtain the existing container struct.
	currCntr, ok := css.usernsTable[inode]
	if !ok {
		css.Unlock()
		logrus.Error("Container update failure: could not find container with user-ns-inode ",
			inode)
		return errors.New("Could not find container to update")
	}

	//
	// Update the existing container-state struct with the one being received.
	// Only 'creation-time' attribute is supported for now.
	//
	currCntr.SetCtime(cntr.ctime)
	css.Unlock()

	logrus.Info(currCntr.String())

	return nil
}

func (css *containerStateService) ContainerDelete(c domain.ContainerIface) error {
	css.Lock()

	cntr := c.(*container)

	//
	// Identify the inode associated to the user-ns of the container being
	// eliminated.
	//
	inode, ok := css.idTable[cntr.id]
	if !ok {
		css.Unlock()
		logrus.Errorf("Container deletion failure: container ID %v not found ", cntr.id)
		return errors.New("Container ID not found")
	}

	currCntr, ok := css.usernsTable[inode]
	if !ok {
		css.Unlock()
		logrus.Errorf("Container deletion error: could not find container with user-inode %v",
			inode)
		return errors.New("Container with userns-inode already present")
	}

	delete(css.idTable, currCntr.id)
	delete(css.usernsTable, inode)
	css.Unlock()

	logrus.Info(currCntr.String())

	return nil
}

func (css *containerStateService) ContainerLookupById(id string) domain.ContainerIface {
	css.RLock()
	defer css.RUnlock()

	usernsInode, ok := css.idTable[id]
	if !ok {
		return nil
	}

	cntr, ok := css.usernsTable[usernsInode]
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
	_, ok = css.idTable[cntr.id]
	if !ok {
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
