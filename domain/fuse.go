//
// Copyright: (C) 2019-2020 Nestybox Inc.  All rights reserved.
//

package domain

type FuseServerServiceIface interface {
	CreateFuseServer(mp string) FuseServerIface
	SetContainerService(css ContainerStateService)
}

type FuseServerIface interface {
	Init() error
	Run() error
	MountPoint() string
	Unmount()
}
