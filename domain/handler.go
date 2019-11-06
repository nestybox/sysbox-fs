//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

package domain

import (
	"os"
	"syscall"
)

type HandlerType int

const (
	NODE_SUBSTITUTION HandlerType = iota // resources that need to be replaced
	NODE_ADITION                         // resources that need to be created / added
)

type Handler struct {
	Name    string
	Path    string
	Type    HandlerType
	Enabled bool
	Service HandlerService
	HandlerIface
}

type HandlerIface interface {
	// FS operations.
	Open(node IOnode, pid uint32) error
	Close(node IOnode) error
	Lookup(n IOnode, pid uint32) (os.FileInfo, error)
	Getattr(n IOnode, pid uint32) (*syscall.Stat_t, error)
	Read(node IOnode, pid uint32, buf []byte, off int64) (int, error)
	Write(node IOnode, pid uint32, buf []byte) (int, error)
	ReadDirAll(node IOnode, pid uint32) ([]os.FileInfo, error)

	// getters/setters.
	GetName() string
	GetPath() string
	GetType() HandlerType
	GetEnabled() bool
	SetEnabled(val bool)
	GetService() HandlerService
	SetService(hs HandlerService)
}

type HandlerService interface {
	RegisterHandler(h HandlerIface) error
	UnregisterHandler(h HandlerIface) error
	LookupHandler(i IOnode) (HandlerIface, bool)
	FindHandler(s string) (HandlerIface, bool)
	EnableHandler(h HandlerIface) error
	DisableHandler(h HandlerIface) error
	DirHandlerEntries(s string) []string
	StateService() ContainerStateService
	NSenterService() NSenterService
	IOService() IOService

	// Auxiliar methods.
	HostPidNsInode() Inode
	FindPidNsInode(pid uint32) Inode
}
