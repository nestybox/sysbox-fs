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

	iradix "github.com/hashicorp/go-immutable-radix"
)

type EmuResourceType int

const (
	UnknownEmuResource EmuResourceType = iota
	DirEmuResource
	FileEmuResource
)

type EmuResource struct {
	Kind  EmuResourceType
	Mode  os.FileMode
	Mutex sync.Mutex
}

// HandlerBase is a type common to all handlers
//
// Note: the "Lock" variable can be used to synchronize across concurrent
// executions of the same handler (e.g., if multiple processes within the same
// sys container or across different sys containers are accessing the same
// sysbox-fs emulated resource). When obtaining the handler lock, only do so to
// synchronize accesses to host resources associated with the emulated resources
// (e.g., if a handler needs to write to the host's procfs for example). While
// holding the handler lock, avoid accessing objects of "container" struct type as
// those have a dedicated lock which is typically held across invocations of the
// handler lock. Violating this rule may result in deadlocks.

type HandlerBase struct {
	Name           string
	Path           string
	EmuResourceMap map[string]EmuResource
	Enabled        bool
	Cacheable      bool
	KernelSync     bool
	Mutex          sync.Mutex
	Service        HandlerServiceIface
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
	SetEnabled(val bool)
	GetService() HandlerServiceIface
	SetService(hs HandlerServiceIface)
	GetResourceMap() map[string]EmuResource
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
	EnableHandler(h HandlerIface) error
	DisableHandler(h HandlerIface) error

	// getters/setter
	HandlerDB() *iradix.Tree
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
