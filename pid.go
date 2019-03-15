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
// pidInodeContainerMap is used to keep track of the mapping between pid-namespaces
// (represented by their corresponding inode), and the associated container-state
// struct.
//
type pidInodeContainerMap struct {
	sync.RWMutex
	internal map[uint64]*containerState
	fs       *sysvisorFS
}

func newPidInodeContainerMap(fs *sysvisorFS) *pidInodeContainerMap {

	pi := &pidInodeContainerMap{
		internal: make(map[uint64]*containerState),
		fs:       fs,
	}

	return pi
}

//
// The following get/set/delete methods *must* be invoked only after
// acquiring the pidInodeMap's mutex by the caller function.
//

func (pi *pidInodeContainerMap) get(key uint64) (*containerState, bool) {

	val, ok := pi.internal[key]

	return val, ok
}

func (pi *pidInodeContainerMap) set(key uint64, value *containerState) {

	pi.internal[key] = value
}

func (pi *pidInodeContainerMap) delete(key uint64) {

	delete(pi.internal, key)
}

// Container registration method, invoked by grpcServer goroutine.
func (pi *pidInodeContainerMap) register(cs *containerState) error {
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

	// Insert the new containerState into the pidInodeContainerMap struct.
	pi.set(cs.pidNsInode, cs)

	//
	// Finalize the registration process by inserting an entry into the
	// containerIdInodeMap.
	//
	pi.fs.containerIDInodeMap.set(cs.id, cs.pidNsInode)

	log.Println("Container registration successfully completed:", cs.String())

	return nil
}

// Container unregistration method, invoked by grpcServer goroutine.
func (pi *pidInodeContainerMap) unregister(cs *containerState) error {

	pi.Lock()
	defer pi.Unlock()

	//
	// Identify the inode associated to the pid-ns of the container being
	// unregistered.
	//
	inode, ok := pi.fs.containerIDInodeMap.get(cs.id)
	if !ok {
		log.Printf("Container unregistration failure: could not find container ",
			" with ID \"%s\"\n", cs.id)
		return errors.New("Could not find container to unregister")
	}
	cs.pidNsInode = inode

	// Eliminate all the existing state associated to this container.
	pi.delete(cs.pidNsInode)
	pi.fs.containerIDInodeMap.delete(cs.id)

	log.Println("Container unregistration successfully completed:", cs.String())

	return nil
}

//
// Function determines if the inode associated to the pid-ns of a given pid is
// already registed in Sysvisorfs.
//
func (pi *pidInodeContainerMap) pidInodeRegistered(pid uint32) bool {

	// Identify the inode associated to this process' pid-ns.
	inode, err := findPidInode(pid)
	if err != nil {
		log.Println("No registered pid", pid, "inode", inode)
		return false
	}

	pi.RLock()
	defer pi.RUnlock()

	if _, ok := pi.get(inode); ok {
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
