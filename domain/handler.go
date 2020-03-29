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

	// True mount nodes. Sysbox-fs supports only two so far: "/proc" and "/sys".
	NODE_MOUNT = 0x4

	// Node entries that need to be bind-mounted for proper emulation. Notice
	// that these ones carry slightly different semantics than SUBSTITUTION
	// ones above.
	// Example: "/proc/meminfo"
	NODE_BINDMOUNT = 0x8

	// Node entries that need to be propagated to L2 containers or L1 chrooted
	// environments. These are typically a subset of BINDMOUNT ones.
	// Example: "/proc/uptime"
	NODE_PROPAGATE = 0x10
)

type HandlerRequest struct {
	ID     uint64
	Pid    uint32
	Uid    uint32
	Gid    uint32
	Offset int64
	Data   []byte
}

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
	Open(node IOnode, req *HandlerRequest) error
	Close(node IOnode) error
	Lookup(n IOnode, req *HandlerRequest) (os.FileInfo, error)
	Getattr(n IOnode, req *HandlerRequest) (*syscall.Stat_t, error)
	Read(node IOnode, req *HandlerRequest) (int, error)
	Write(node IOnode, req *HandlerRequest) (int, error)
	ReadDirAll(node IOnode, req *HandlerRequest) ([]os.FileInfo, error)

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

	// getters/setter
	HandlerDB() map[string]HandlerIface
	StateService() ContainerStateService
	ProcessService() ProcessService
	NSenterService() NSenterService
	IOService() IOService
	IgnoreErrors() bool

	// Auxiliar methods.
	HostUserNsInode() Inode
	FindUserNsInode(pid uint32) Inode
}
