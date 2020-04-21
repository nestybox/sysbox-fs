//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

package domain

import (
	"os"
	"syscall"
)

type HandlerType int

// These constants define the way in which sysbox-fs sets up resources under filesystems
// that it emulates (e.g., procfs or sysfs).
const (
	// Node entries that need to be substituted (or added) for proper emulation.
	// Examples:
	//  - "/proc/sys/kernel/panic" (substituted to allow RW access)
	//  - "/proc/sys/net/netfilter/nf_conntrack_max" (added as node not present
	//	outside init network-ns).
	NODE_SUBSTITUTION = 0x1

	// Base mount nodes. Sysbox-fs supports only two so far: "/proc" and "/sys".
	NODE_MOUNT = 0x2

	// Node entries that need to be bind-mounted for proper emulation. Notice
	// that these ones carry slightly different semantics than SUBSTITUTION
	// ones above.
	// Example: "/proc/meminfo"
	NODE_BINDMOUNT = 0x4

	// Node entries that need to be propagated to L2 containers or L1 chrooted
	// environments. These are typically a subset of BINDMOUNT ones.
	// Example: "/proc/uptime"
	//
	// NOTE: these are only needed because sysbox-fs has handlers that are currently just
	// place-holders. Otherwise propagate would be equal to bindmount.
	NODE_PROPAGATE = 0x8
)

type HandlerRequest struct {
	ID        uint64
	Pid       uint32
	Uid       uint32
	Gid       uint32
	Offset    int64
	Data      []byte
	Container ContainerIface
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
	SetStateService(css ContainerStateService)
	ProcessService() ProcessService
	NSenterService() NSenterService
	IOService() IOService
	IgnoreErrors() bool

	// Auxiliar methods.
	HostUserNsInode() Inode
	FindUserNsInode(pid uint32) Inode
}
