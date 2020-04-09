//
// Copyright: (C) 2019-2020 Nestybox Inc.  All rights reserved.
//

package domain

type FuseServerServiceIface interface {
	CreateFuseServer(mp string) error
	DestroyFuseServer(mp string) error
	SetContainerService(css ContainerStateService)
	DestroyFuseService()
}

type FuseServerIface interface {
	Init() error
	Run() error
	Destroy() error
	MountPoint() string
	Unmount()
}
