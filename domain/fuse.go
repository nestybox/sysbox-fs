//
// Copyright: (C) 2019-2020 Nestybox Inc.  All rights reserved.
//

package domain

type FuseServerServiceIface interface {
	Setup(
		mp string,
		css ContainerStateServiceIface,
		ios IOServiceIface,
		hds HandlerServiceIface)

	CreateFuseServer(cntr ContainerIface) error
	DestroyFuseServer(mp string) error
	DestroyFuseService()
}

type FuseServerIface interface {
	Create() error
	Run() error
	Destroy() error
	MountPoint() string
	Unmount()
	InitWait()
}
