//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

package state

import (
	"errors"
	"strconv"
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

	// Map to keep track of the association between container's pid-namespaces
	// (inode) and the internal structure to hold all the container state.
	pidTable map[domain.Inode]*container

	// Pointer to the service providing file-system I/O capabilities.
	ios domain.IOService
}

func NewContainerStateService(ios domain.IOService) domain.ContainerStateService {

	newCSS := &containerStateService{
		idTable:  make(map[string]domain.Inode),
		pidTable: make(map[domain.Inode]*container),
		ios:      ios,
	}

	return newCSS
}

func (css *containerStateService) ContainerCreate(
	id string,
	initpid uint32,
	inode domain.Inode,
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
		initPid:       initpid,
		pidInode:      inode,
		ctime:         ctime,
		uidFirst:      uidFirst,
		uidSize:       uidSize,
		gidFirst:      gidFirst,
		gidSize:       gidSize,
		procRoPaths:   procRoPaths,
		procMaskPaths: procMaskPaths,
	}

	for _, v := range newcntr.procRoPaths {
		logrus.Errorf("ropath: %v", v)
	}
	for _, v := range newcntr.procMaskPaths {
		logrus.Errorf("maskpath: %v", v)
	}

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

	// Ensure that new container's pidNsInode is not already registered.
	if _, ok := css.pidTable[cntr.pidInode]; ok {
		css.Unlock()
		logrus.Errorf("Container addition error: container with PID-inode %v already present", cntr.pidInode)
		return errors.New("Container with PID-inode already present")
	}

	css.idTable[cntr.id] = cntr.pidInode
	css.pidTable[cntr.pidInode] = cntr
	css.Unlock()

	logrus.Info(cntr.String())

	return nil
}

func (css *containerStateService) ContainerUpdate(c domain.ContainerIface) error {
	css.Lock()

	cntr := c.(*container)

	//
	// Identify the inode associated to the pid-ns of the container being
	// updated.
	//
	inode, ok := css.idTable[cntr.id]
	if !ok {
		css.Unlock()
		logrus.Errorf("Container update failure: container ID %v not found", cntr.id)
		return errors.New("Container ID not found")
	}

	// Obtain the existing container struct.
	currCntr, ok := css.pidTable[inode]
	if !ok {
		css.Unlock()
		logrus.Error("Container update failure: could not find container with pid-ns-inode ", inode)
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
	// Identify the inode associated to the pid-ns of the container being
	// eliminated.
	//
	inode, ok := css.idTable[cntr.id]
	if !ok {
		css.Unlock()
		logrus.Errorf("Container deletion failure: container ID %v not found ", cntr.id)
		return errors.New("Container ID not found")
	}

	currCntr, ok := css.pidTable[inode]
	if !ok {
		css.Unlock()
		logrus.Error("Container deletion error: could not find container with PID-inode ", inode)
		return errors.New("Container with PID-inode already present")
	}

	delete(css.idTable, currCntr.id)
	delete(css.pidTable, inode)
	css.Unlock()

	logrus.Info(currCntr.String())

	return nil
}

func (css *containerStateService) ContainerLookupById(id string) domain.ContainerIface {
	css.RLock()
	defer css.RUnlock()

	pidInode, ok := css.idTable[id]
	if !ok {
		return nil
	}

	cntr, ok := css.pidTable[pidInode]
	if !ok {
		return nil
	}

	return cntr
}

func (css *containerStateService) ContainerLookupByInode(pidInode domain.Inode) domain.ContainerIface {
	css.RLock()
	defer css.RUnlock()

	cntr, ok := css.pidTable[pidInode]
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

func (css *containerStateService) ContainerLookupByPid(pid uint32) domain.ContainerIface {

	// Identify the pidNsInode corresponding to this pid.
	ionode := css.ios.NewIOnode("", strconv.Itoa(int(pid)), 0)
	pidInode, err := css.ios.PidNsInode(ionode)
	if err != nil {
		return nil
	}

	// Find the container-state corresponding to the container hosting this
	// Pid.
	cntr := css.ContainerLookupByInode(pidInode)
	if cntr == nil {
		// If no container is found then determine if we are dealing with a nested
		// container scenario. If that's the case, it's natural to expect sysbox-fs
		// to be totally unaware of L2 containers launching this request, so we
		// would be tempted to discard it. To avoid that we obtain the parent pid
		// namespace (and its associated inode), and we search through containerDB
		// once again. If there's a match then we serve this request making use of
		// the parent (L1) system container state.
		parentPidInode, err := css.ios.PidNsInodeParent(ionode)
		if err != nil {
			logrus.Errorf("Could not identify a parent namespace for pid %v", pid)
			return nil
		}

		parentCntr := css.ContainerLookupByInode(parentPidInode)
		if parentCntr == nil {
			logrus.Errorf("Could not find the container originating this request (pidNsInode %v)",
				pidInode)
			return nil
		}

		return parentCntr
	}

	return cntr
}
