package main

import (
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

//
// File contains the logic necessary to maintain the state corresponding to
// pid-namespaces and their associated inodes.
//

//
// pidNsContainerMap is used to keep track of the mapping between pid-namespaces
// (represented by their corresponding inode), and the container (id) associated
// to this pid-namespace.
//
type pidNsContainerMap struct {
	sync.RWMutex
	internal map[uint64]string
}

func newPidNsContainerMap() *pidNsContainerMap {

	pn := &pidNsContainerMap{
		internal: make(map[uint64]string),
	}

	return pn
}

func (pn *pidNsContainerMap) get(key uint64) (value string, ok bool) {

	pn.RLock()
	res, ok := pn.internal[key]
	pn.RUnlock()

	return res, ok
}

func (pn *pidNsContainerMap) set(key uint64, value string) {

	pn.Lock()
	pn.internal[key] = value
	pn.Unlock()
}

func (pn *pidNsContainerMap) delete(key uint64) {

	pn.Lock()
	delete(pn.internal, key)
	pn.Unlock()
}

func (pn *pidNsContainerMap) lookup(key uint64) (string, bool) {

	cntrId, ok := pn.get(key)
	if !ok {
		return "", false
	}

	return cntrId, true
}

//
// Miscelaneous utilities dealing with pid-ns-inode state.
//

//
// Function in charge of identifying the inode associated to the pid-ns of any
// given process (pid).
//
func getPidNsInode(pid uint32) (uint64, error) {

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

//
// Function determines if the inode associated to the pid-ns of a given pid is
// already registed in Sysvisorfs.
//
func pidNsRegistered(pid uint32, fs *sysvisorFS) bool {

	// Identify the inode for the pid-ns first
	inode, err := getPidNsInode(pid)
	if err != nil {
		log.Println("No registered pid", pid, "inode", inode)
		return false
	}

	//if _, ok := PidNsContainerMapGlobal.lookup(inode); ok {
	if _, ok := fs.pidNsCntrMap.lookup(inode); ok {
		return true
	}

	return false
}
