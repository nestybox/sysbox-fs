//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

package domain

type FuseService interface {
	Run() error
	MountPoint() string
	Unmount()
}
