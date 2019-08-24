package sysio

import (
	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
)

type IOServiceType = int

const (
	Unknown IOServiceType = iota
	IOFileService
	IOBufferService
)

func NewIOService(t IOServiceType) domain.IOService {

	switch t {

	case IOFileService:
		return &ioFileService{}

	//case IOBufferNode:
	//	return &ioBufferService{}

	default:
		logrus.Panic("Unsupported ioService required: ", t)
	}

	return nil
}
