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
	idTable  map[string]domain.Inode
	pidTable map[domain.Inode]*container
}

func NewContainerStateService() domain.ContainerStateService {

	newCSS := &containerStateService{
		idTable:  make(map[string]domain.Inode),
		pidTable: make(map[domain.Inode]*container),
	}

	return newCSS
}

func (css *containerStateService) ContainerCreate(
	id string,
	initpid uint32,
	hostname string,
	inode domain.Inode,
	ctime time.Time,
	uidFirst uint32,
	uidSize uint32,
	gidFirst uint32,
	gidSize uint32,
) domain.ContainerIface {

	newcntr := &container{
		id:       id,
		initPid:  initpid,
		hostname: hostname,
		pidInode: inode,
		ctime:    ctime,
		uidFirst: uidFirst,
		uidSize:  uidSize,
		gidFirst: gidFirst,
		gidSize:  gidSize,
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

func (css *containerStateService) ContainerLookupByPid(pidInode domain.Inode) domain.ContainerIface {
	css.RLock()
	defer css.RUnlock()

	cntr, ok := css.pidTable[pidInode]
	if !ok {
		return nil
	}

	// Althought not strickly needed, let's check in container's idTable too for
	// data-consistency's sake.
	_, ok = css.idTable[cntr.id]
	if !ok {
		return nil
	}

	return cntr
}
