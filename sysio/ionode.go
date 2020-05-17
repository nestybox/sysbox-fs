//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

package sysio

import (
	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
)

func NewIOService(t domain.IOServiceType) domain.IOServiceIface {

	switch t {

	case domain.IOOsFileService:
		return newIOFileService(domain.IOOsFileService)

	case domain.IOMemFileService:
		return newIOFileService(domain.IOMemFileService)

	//case domain.IOBufferNode:
	//	return &ioBufferService{}

	default:
		logrus.Panic("Unsupported ioService required: ", t)
	}

	return nil
}
