package main

import (
	"errors"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

//
// File contains the logic necessary to maintain the state corresponding to
// pid-namespace-inodes and their associated container-state structs.
//

//
// pidInodeMap is used to keep track of the mapping between pid-namespaces
// (represented by their corresponding inode), and the associated container-state
// struct.
//
type pidInodeMap struct {
	sync.RWMutex
	internal map[uint64]*containerState
}

func newPidInodeMap() *pidInodeMap {

	pi := &pidInodeMap{
		internal: make(map[uint64]*containerState),
	}

	return pi
}

//
// The following get/set/delete/lookup methods *must* be invoked only after
// acquiring the pidInodeMap's mutex by the caller function.
//

func (pi *pidInodeMap) get(key uint64) (*containerState, bool) {

	val, ok := pi.internal[key]

	return val, ok
}

func (pi *pidInodeMap) set(key uint64, value *containerState) {

	pi.internal[key] = value
}

func (pi *pidInodeMap) delete(key uint64) {

	delete(pi.internal, key)
}

func (pi *pidInodeMap) lookup(key uint64) (*containerState, bool) {

	cntr, ok := pi.get(key)
	if !ok {
		return nil, false
	}

	return cntr, true
}

// Container registration method.
func (pi *pidInodeMap) register(cs *containerState) error {
	//
	// Identify the inode corresponding to the pid-namespace associated to this
	// containerState struct.
	//
	inode, err := findPidInode(cs.initPid)
	if err != nil {
		log.Printf("Could not find ns-inode for pid %d\n", cs.initPid)
		return errors.New("Could not find pid-namespace inode for pid")
	}
	cs.pidNsInode = inode

	pi.Lock()
	defer pi.Unlock()

	//
	// Verify that the new container to create is not already present in this
	// pidInodeMap.
	//
	if _, ok := pi.get((uint64)(cs.pidNsInode)); ok {
		log.Printf("Container with pidInode %d is already registered\n",
			cs.pidNsInode)
		return errors.New("Container already registered")
	}

	//
	// Finalize registration process by inserting the containerState into the
	// pidInodeMap struct.
	//
	pi.set(cs.pidNsInode, cs)

	log.Println("Container registration successfully completed:", cs.String())

	return nil
}

// Container unregistration method.
func (pi *pidInodeMap) unregister(cs *containerState) error {

	pi.Lock()
	defer pi.Unlock()

	cntrFound := false
	//
	// Iterate through all pidInodeMap looking for the matching container.
	// Notice that we must incur in this linear cost due to the fact that, by
	// the time that the container is unregistered --runc calls cntr.destroy()--
	// pid-ns has been already teared apart, so we can't obtain the inode
	// corresponding to the container's pid-ns.
	//
	for _, val := range pi.internal {
		if val.initPid == cs.initPid &&
			val.id == cs.id {
			cs = val
			cntrFound = true
			break
		}
	}
	if !cntrFound {
		log.Printf("Container unregistration failure: could not find container ",
			"with initPid \"%d\"", cs.initPid)
		return errors.New("Could not find container to unregister")
	}

	// Eliminate the existing container-state.
	pi.delete(cs.pidNsInode)

	log.Println("Container unregistration successfully completed:", cs.String())

	return nil
}

//
// Function determines if the inode associated to the pid-ns of a given pid is
// already registed in Sysvisorfs.
//
func (pi *pidInodeMap) pidInodeRegistered(pid uint32) bool {

	// Identify the inode associated to this process' pid-ns.
	inode, err := findPidInode(pid)
	if err != nil {
		log.Println("No registered pid", pid, "inode", inode)
		return false
	}

	pi.RLock()
	defer pi.RUnlock()

	if _, ok := pi.lookup(inode); ok {
		return true
	}

	return false
}

//
// Miscelaneous utilities dealing with pid-ns-inode state.
//

//
// Function in charge of identifying the inode associated to the pid-ns of any
// given process (pid).
//
func findPidInode(pid uint32) (uint64, error) {

	pidnsPath := strings.Join([]string{
		"/proc",
		strconv.FormatUint(uint64(pid), 10),
		"ns/pid"}, "/")

	// Extract pid-ns info from FS
	info, err := os.Stat(pidnsPath)
	if err != nil {
		log.Println("No process file found for pid:", pid)
		return 0, err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		log.Println("Not a syscall.Stat_t")
		return 0, nil
	}

	log.Println("pidNsInode pid", pid, "inode", stat.Ino)

	return stat.Ino, nil
}
