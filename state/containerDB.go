package state

import (
	"errors"
	"log"
	"sync"

	"github.com/nestybox/sysvisor/sysvisor-fs/domain"
)

type containerStateService struct {
	sync.RWMutex
	idTable  map[string]domain.Inode
	pidTable map[domain.Inode]*domain.Container
}

func NewContainerStateService() domain.ContainerStateService {

	newCSS := &containerStateService{
		idTable:  make(map[string]domain.Inode),
		pidTable: make(map[domain.Inode]*domain.Container),
	}

	return newCSS
}

func (css *containerStateService) ContainerCreate(
	id string,
	initpid uint32,
	hostname string,
	inode domain.Inode) *domain.Container {

	newcntr := &domain.Container{
		ID:       id,
		InitPid:  initpid,
		Hostname: hostname,
		PidInode: inode,
		Data:     make(map[string]map[string]string),
	}

	return newcntr
}

func (css *containerStateService) ContainerAdd(c *domain.Container) error {
	css.Lock()

	if _, ok := css.idTable[c.ID]; ok {
		css.Unlock()
		log.Printf("Container addition error: container ID %v already present\n", c.ID)
		return errors.New("Container ID already present")
	}

	if _, ok := css.pidTable[c.PidInode]; ok {
		css.Unlock()
		log.Printf("Container addition error: container with PID-inode %v already present\n", c.PidInode)
		return errors.New("Container with PID-inode already present")
	}

	css.idTable[c.ID] = c.PidInode
	css.pidTable[c.PidInode] = c
	css.Unlock()

	return nil
}

func (css *containerStateService) ContainerUpdate(c *domain.Container) error {
	css.Lock()

	//
	// Identify the inode associated to the pid-ns of the container being
	// updated.
	//
	inode, ok := css.idTable[c.ID]
	if !ok {
		css.Unlock()
		log.Printf("Container update failure: container ID %v not found\n", c.ID)
		return errors.New("Container ID not found")
	}

	// Obtain the existing container struct.
	currCntr, ok := css.pidTable[inode]
	if !ok {
		css.Unlock()
		log.Println("Container update failure: could not find container with pid-ns-inode", inode)
		return errors.New("Could not find container to update")
	}

	//
	// Update the existing container-state struct with the one being received.
	// Only 'creation-time' attribute is supported for now.
	//
	currCntr.Ctime = c.Ctime
	css.Unlock()

	return nil
}

func (css *containerStateService) ContainerDelete(c *domain.Container) error {
	css.Lock()

	//
	// Identify the inode associated to the pid-ns of the container being
	// eliminated.
	//
	inode, ok := css.idTable[c.ID]
	if !ok {
		css.Unlock()
		log.Printf("Container deletion failure: container ID %v not found\n", c.ID)
		return errors.New("Container ID not found")
	}

	if _, ok := css.pidTable[inode]; !ok {
		css.Unlock()
		log.Println("Container deletion error: could not find container with PID-inode", inode)
		return errors.New("Container with PID-inode already present")
	}

	delete(css.idTable, c.ID)
	delete(css.pidTable, inode)
	css.Unlock()

	return nil
}

func (css *containerStateService) ContainerLookupById(id string) *domain.Container {
	css.RLock()
	defer css.RUnlock()

	pidInode, ok := css.idTable[id]
	if !ok {
		return nil
	}

	cont, ok := css.pidTable[pidInode]
	if !ok {
		return nil
	}

	return cont
}

func (css *containerStateService) ContainerLookupByPid(pidInode domain.Inode) *domain.Container {
	css.RLock()
	defer css.RUnlock()

	cont, ok := css.pidTable[pidInode]
	if !ok {
		return nil
	}

	return cont
}
