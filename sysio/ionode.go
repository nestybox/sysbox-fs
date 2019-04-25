package sysio

import (
	"log"

	"github.com/nestybox/sysvisor/sysvisor-fs/domain"
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
		log.Panicf("Unsupported ioService required: %v", t)
	}

	return nil
}
