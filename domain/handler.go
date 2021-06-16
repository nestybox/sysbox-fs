//
// Copyright 2019-2020 Nestybox, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package domain

import (
	"os"
	"sync"
)

// HandlerBase is a type common to all the handlers.
//
// HandlerBase type is used to bundle the different file-system operations that
// can be executed over sysbox-fs' emulated resources. As such, handlers are
// typically associated with a directory path inside of which there is at least
// one resource (file or subdir) that needs to be emulated.
//
// Handlers can be paired with a file too though, but usually they are associated
// with directories to leverage the fact that, within a given directory, there
// are commonalities among the resources being emulated. Hence, this approach
// reduces the amount of duplicated code that would otherwise derive from
// handler sprawling.
//
// The handler resources being emulated are stored within a map indexed by the
// resource name.
type HandlerBase struct {
	// Camel-case representation of every handler path.
	Name string

	// Full FS path of the node being served by every handler.
	Path string

	// Map of resources served within every handler.
	EmuResourceMap map[string]*EmuResource

	Enabled bool

	// Pointer to the parent handler service.
	Service HandlerServiceIface
}

type EmuResourceType int

const (
	UnknownEmuResource EmuResourceType = iota
	DirEmuResource
	FileEmuResource
)

// EmuResource represents the nodes being emulated by sysbox-fs.
//
// The "mutex" variable is utilized to synchronize access among concurrent i/o
// operations made over the same host resource (e.g. if multiple processes within
// the same sys container or across different sys containers are accessing the
// same sysbox-fs emulated resource). By relying on a per-resource "mutex", and
// not a per-handler one, we are maximizing the level of concurrency that can be
// attained.
type EmuResource struct {
	Kind    EmuResourceType
	Mode    os.FileMode
	Enabled bool
	Mutex   sync.Mutex
}

// HandlerRequest represents a request to be processed by a handler
type HandlerRequest struct {
	ID        uint64
	Pid       uint32
	Uid       uint32
	Gid       uint32
	Offset    int64
	Data      []byte
	Container ContainerIface
}

// HandlerIface is the interface that each handler must implement
type HandlerIface interface {
	// FS operations.
	Open(node IOnodeIface, req *HandlerRequest) error
	Lookup(n IOnodeIface, req *HandlerRequest) (os.FileInfo, error)
	Read(node IOnodeIface, req *HandlerRequest) (int, error)
	Write(node IOnodeIface, req *HandlerRequest) (int, error)
	ReadDirAll(node IOnodeIface, req *HandlerRequest) ([]os.FileInfo, error)

	// getters/setters.
	GetName() string
	GetPath() string
	GetEnabled() bool
	SetEnabled(b bool)
	GetService() HandlerServiceIface
	SetService(hs HandlerServiceIface)
	GetResourcesList() []string
	GetResourceMutex(s string) *sync.Mutex
}

type HandlerServiceIface interface {
	Setup(
		hdlrs []HandlerIface,
		ignoreErrors bool,
		css ContainerStateServiceIface,
		nss NSenterServiceIface,
		prs ProcessServiceIface,
		ios IOServiceIface)

	RegisterHandler(h HandlerIface) error
	UnregisterHandler(h HandlerIface) error
	LookupHandler(i IOnodeIface) (HandlerIface, bool)
	FindHandler(s string) (HandlerIface, bool)
	EnableHandler(path string) error
	DisableHandler(path string) error

	// getters/setters
	HandlersResourcesList() []string
	GetPassThroughHandler() HandlerIface
	StateService() ContainerStateServiceIface
	SetStateService(css ContainerStateServiceIface)
	ProcessService() ProcessServiceIface
	NSenterService() NSenterServiceIface
	IOService() IOServiceIface
	IgnoreErrors() bool

	// Auxiliar methods.
	HostUserNsInode() Inode
	FindUserNsInode(pid uint32) (Inode, error)
}
