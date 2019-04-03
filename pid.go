package main

import (
	"errors"
	"log"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/spf13/afero"
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

//
// Notice that lookup() method differs from get() one, as this one is expected
// to be utilized by goroutines other than grpcServer one, and as such, it deals
// himself with thread-safety concerns.
//
func (pi *pidInodeContainerMap) lookup(key uint64) (*containerState, bool) {

	pi.RLock()
	defer pi.RUnlock()

	cs, ok := pi.get(key)
	if !ok {
		return nil, false
	}

	return cs, true
}

// Container registration method, invoked by grpcServer goroutine.
func (pi *pidInodeContainerMap) register(cs *containerState) error {
	//
	// Identify the inode corresponding to the pid-namespace associated to this
	// containerState struct.
	//
	inode, err := findInodeByPid(cs.initPid)
	if err != nil {
		log.Printf("Could not find ns-inode for pid %d\n", cs.initPid)
		return errors.New("Could not find pid-namespace inode for pid")
	}
	cs.pidNsInode = inode

	pi.Lock()
	defer pi.Unlock()

	//
	// Verify that the new container to register is not already present in this
	// pidInodeMap.
	//
	if _, ok := pi.get((uint64)(cs.pidNsInode)); ok {
		log.Printf("Container with pidInode %d is already registered\n",
			cs.pidNsInode)
		return errors.New("Container already registered")
	}

	//
	// Verify that the associated container-id is not already present in the
	// global containerIDnodeMap, and if that's not the case, proceed to insert
	// it.
	//
	if _, ok := pi.fs.containerIDInodeMap.get(cs.id); ok {
		log.Printf("Container with id %s is already registered\n", cs.id)
		return errors.New("Container already registered")
	}
	pi.fs.containerIDInodeMap.set(cs.id, cs.pidNsInode)

	// Insert the new containerState into the pidInodeContainerMap struct.
	pi.set(cs.pidNsInode, cs)

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
		log.Printf("Container unregistration failure: could not find container with ID %s\n", cs.id)
		return errors.New("Could not find container to unregister")
	}

	//
	// Obtain the existing container-state struct, which contains a more
	// complete view than the one held by "cs" parameter during unregistration
	// phase.
	//
	currentCs, ok := pi.fs.pidInodeContainerMap.get(inode)
	if !ok {
		log.Printf("Container unregistration failure: could not find container with pid-ns-inode %d\n", inode)
		return errors.New("Could not find container to unregister")
	}

	// Eliminate all the existing state associated to this container.
	pi.fs.containerIDInodeMap.delete(currentCs.id)
	pi.delete(inode)

	log.Println("Container unregistration successfully completed:",
		currentCs.String())

	return nil
}

//
// TODO: A bit of a stretch placing this method here as it symantically
// belongs within containerState class. Think about improving this.
//
// Container state-update method, invoked by grpcServer goroutine.
func (pi *pidInodeContainerMap) update(cs *containerState) error {

	pi.Lock()
	defer pi.Unlock()

	//
	// Identify the inode associated to the pid-ns of the container being
	// unregistered.
	//
	inode, ok := pi.fs.containerIDInodeMap.get(cs.id)
	if !ok {
		log.Printf("Container update failure: could not find container with ID \"%s\"\n", cs.id)
		return errors.New("Could not find container to update")
	}

	// Obtain the existing container-state struct.
	currentCs, ok := pi.fs.pidInodeContainerMap.get(inode)
	if !ok {
		log.Printf("Container update failure: could not find container with pid-ns-inode \"%d\"\n", inode)
		return errors.New("Could not find container to update")
	}

	//
	// Update the existing container-state struct with the one being received.
	// Only 'creation-time' attribute is supported for now.
	//
	currentCs.ctime = cs.ctime

	log.Println("Container update successfully completed:",
		currentCs.String())

	return nil
}

//
// Function determines if the inode associated to the pid-ns of a given pid is
// already registed in Sysvisorfs.
//
func (pi *pidInodeContainerMap) pidInodeRegistered(pid uint32) bool {

	// Identify the inode associated to this process' pid-ns.
	inode, err := findInodeByPid(pid)
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
// Miscelaneous func utilities dealing with pid-ns-inode state and pid-related
// logic.
//

//
// Function in charge of identifying the inode associated to the pid-ns of any
// given process (pid).
//
func findInodeByPid(pid uint32) (uint64, error) {

	pidnsPath := strings.Join([]string{
		"/proc",
		strconv.FormatUint(uint64(pid), 10),
		"ns/pid"}, "/")

	// Extract pid-ns info from FS.
	//info, err := os.Stat(pidnsPath)
	info, err := appFS.Stat(pidnsPath)
	if err != nil {
		log.Println("No process file found for pid:", pid)
		return 0, err
	}

	if unitTesting {
		content, err := afero.ReadFile(appFS, pidnsPath)
		if err != nil {
			return 0, err
		}
		res, err := strconv.ParseUint(string(content), 10, 64)

		return res, nil
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		log.Println("Not a syscall.Stat_t")
		return 0, nil
	}

	log.Println("pidNsInode pid", pid, "inode", stat.Ino)

	return stat.Ino, nil
}

//
// Function obtains the container-state struct associated to the container
// from which any given I/O operation is launched. This operation is
// represented by the Pid associated to the process generating the request.
//
func findContainerByPid(pid uint32) (*containerState, error) {

	//
	// Identify the inode corresponding to the pid-namespace associated to this
	// container.
	//
	inode, err := findInodeByPid(pid)
	if err != nil {
		return nil, errors.New("Could not find pid-namespace inode for pid")
	}

	// Find the container from which this request is generated from.
	//spew.Dump(sysfs.pidInodeContainerMap)
	cs, ok := sysfs.pidInodeContainerMap.lookup(inode)
	if !ok {
		return nil, errors.New("Could not find container")
	}

	return cs, nil
}
