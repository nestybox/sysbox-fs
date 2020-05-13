//
// Copyright: (C) 2019-2020 Nestybox Inc.  All rights reserved.
//

package domain

type FuseServerServiceIface interface {
	CreateFuseServer(cntr ContainerIface) error
	DestroyFuseServer(mp string) error
	SetContainerService(css ContainerStateServiceIface)
	DestroyFuseService()
}

type FuseServerIface interface {
	Create() error
	Run() error
	Destroy() error
	MountPoint() string
	Unmount()
}
