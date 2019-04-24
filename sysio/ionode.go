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

/*
func (s *ioService) OpenNode(i IOnode) error {
	return s.ops.Open(i)
}

func (s *ioService) ReadNode(i IOnode, p []byte) (int, error) {
	return s.ops.Read(i, p)
}

func (s *ioService) WriteNode(i IOnode, p []byte) (int, error) {
	return s.ops.Write(i, p)
}

func (s *ioService) CloseNode(i IOnode) error {
	return s.ops.Close(i)
}

func (s *ioService) ReadAtNode(i IOnode, p []byte, off int64) (int, error) {
	return s.ops.ReadAt(i, p, off)
}

func (s *ioService) ReadDirAllNode(i IOnode) ([]os.FileInfo, error) {
	return s.ops.ReadDirAll(i)
}
*/
