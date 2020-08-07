
package domain

import "time"

//
// Container interface.
//
type ContainerIface interface {
	//
	// Getters
	//
	ID() string
	InitPid() uint32
	Ctime() time.Time
	Data(path string, name string) (string, bool)
	String() string
	UID() uint32
	GID() uint32
	ProcRoPaths() []string
	ProcMaskPaths() []string
	IsSpecPath(s string) bool
	InitProc() ProcessIface
	//
	// Setters
	//
	//Update(cntr ContainerIface) error
	SetData(path string, name string, data string)
	SetInitProc(pid, uid, gid uint32) error
	SetService(css ContainerStateServiceIface)
}

//
// Auxiliary types to deal with the per-container-state associated to all the
// emulated resources.
//
type StateDataMap = map[string]map[string]string
type StateData = map[string]string

//
// ContainerStateService interface defines the APIs that sysbox-fs components
// must utilize to interact with the sysbox-fs state-storage backend.
//
type ContainerStateServiceIface interface {
	Setup(
		fss FuseServerServiceIface,
		prs ProcessServiceIface,
		ios IOServiceIface)

	ContainerCreate(
		id string,
		pid uint32,
		ctime time.Time,
		uidFirst uint32,
		uidSize uint32,
		gidFirst uint32,
		gidSize uint32,
		procRoPaths []string,
		procMaskPaths []string) ContainerIface

	ContainerPreRegister(id string) error
	ContainerRegister(c ContainerIface) error
	ContainerUpdate(c ContainerIface) error
	ContainerUnregister(c ContainerIface) error
	ContainerLookupById(id string) ContainerIface
	ContainerLookupByInode(usernsInode Inode) ContainerIface
	ContainerLookupByProcess(process ProcessIface) ContainerIface
	FuseServerService() FuseServerServiceIface
	ProcessService() ProcessServiceIface
	ContainerDBSize() int
}
