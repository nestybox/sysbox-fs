//
// Copyright: (C) 2019-2020 Nestybox Inc.  All rights reserved.
//

package domain

type IpcServiceIface interface {
	Setup(
		css ContainerStateServiceIface,
		prs ProcessServiceIface,
		ios IOServiceIface)

	Init() error
}
