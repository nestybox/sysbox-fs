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
	// Node entries that need to be replaced for proper emulation.
	// Example: "/proc/sys/kernel/panic"
	NODE_SUBSTITUTION = 0x1

	// Node entries that need to be added to enhance virtual-host experience.
	// Example: "/proc/sys/net/netfilter/nf_conntrack_max"
	NODE_ADITION = 0x2

	// Node entries that need to be bind-mounted for proper emulation. Notice
	// that these ones carry slightly different semantics than SUBSTITUTION
	// ones above.
	// Example: "/proc/meminfo"
	NODE_BINDMOUNT = 0x4

	// Node entries that need to be propagated to L2 containers or L1 chrooted
	// environments. These are typically a subset of BINDMOUNT ones.
	// Example: "/proc/uptime"
	NODE_PROPAGATE = 0x8
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
	GetBindMount() bool
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

	// getters/setter
	HandlerDB() map[string]HandlerIface
	StateService() ContainerStateService
	NSenterService() NSenterService
	IOService() IOService

	// Auxiliar methods.
	HostPidNsInode() Inode
	FindPidNsInode(pid uint32) Inode
}
