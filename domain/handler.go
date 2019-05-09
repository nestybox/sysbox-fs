package domain

import (
	"os"
	"syscall"
)

type Handler struct {
	Name    string
	Path    string
	Enabled bool
	Service HandlerService
	HandlerIface
}

type HandlerIface interface {
	// FS operations.
	Open(node IOnode) error
	Close(node IOnode) error
	Lookup(n IOnode, pid uint32) (os.FileInfo, error)
	Getattr(n IOnode, pid uint32) (*syscall.Stat_t, error)
	Read(node IOnode, pid uint32, buf []byte, off int64) (int, error)
	Write(node IOnode, pid uint32, buf []byte) (int, error)
	ReadDirAll(node IOnode, pid uint32) ([]os.FileInfo, error)

	// getters/setters.
	GetName() string
	GetPath() string
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
	IOService() IOService
}
