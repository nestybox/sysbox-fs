//
// Copyright 2019-2023 Nestybox, Inc.
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

// Aliases to leverage strong-typing.
type NStype = string
type NSenterMsgType = string

// NStype defines all namespace types
const (
	NStypeCgroup NStype = "cgroup"
	NStypeIpc    NStype = "ipc"
	NStypeNet    NStype = "net"
	NStypePid    NStype = "pid"
	NStypeUts    NStype = "uts"
	NStypeUser   NStype = "user"
	NStypeMount  NStype = "mnt"
)

// Security note: nsenter processes spawned by sysbox-fs that enter the pid
// namespace must also enter the container's mount ns, as otherwise the nsenter
// process will inherit sysbox-fs host mounts, resulting in a process inside the
// container that exposes info about those mounts. If needed, the nsenter
// process can always unshare the mount ns inside the container so that it can
// perform mounts without affecting the container processes.

var AllNSs = []NStype{
	string(NStypeUser),
	string(NStypePid),
	string(NStypeNet),
	string(NStypeMount),
	string(NStypeIpc),
	string(NStypeCgroup),
	string(NStypeUts),
}

var AllNSsButUser = []NStype{
	string(NStypeMount),
	string(NStypePid),
	string(NStypeNet),
	string(NStypeIpc),
	string(NStypeCgroup),
	string(NStypeUts),
}

// NSenterEvent types. Define all possible messages that can be handled
// by nsenterEvent class.
const (
	LookupRequest              NSenterMsgType = "lookupRequest"
	LookupResponse             NSenterMsgType = "lookupResponse"
	OpenFileRequest            NSenterMsgType = "openFileRequest"
	OpenFileResponse           NSenterMsgType = "openFileResponse"
	ReadFileRequest            NSenterMsgType = "readFileRequest"
	ReadFileResponse           NSenterMsgType = "readFileResponse"
	WriteFileRequest           NSenterMsgType = "writeFileRequest"
	WriteFileResponse          NSenterMsgType = "writeFileResponse"
	ReadDirRequest             NSenterMsgType = "readDirRequest"
	ReadDirResponse            NSenterMsgType = "readDirResponse"
	ReadLinkRequest            NSenterMsgType = "readLinkRequest"
	ReadLinkResponse           NSenterMsgType = "readLinkResponse"
	MountSyscallRequest        NSenterMsgType = "mountSyscallRequest"
	MountSyscallResponse       NSenterMsgType = "mountSyscallResponse"
	UmountSyscallRequest       NSenterMsgType = "umountSyscallRequest"
	UmountSyscallResponse      NSenterMsgType = "umountSyscallResponse"
	ChownSyscallRequest        NSenterMsgType = "chownSyscallRequest"
	ChownSyscallResponse       NSenterMsgType = "chownSyscallResponse"
	MountInfoRequest           NSenterMsgType = "mountInfoRequest"
	MountInfoResponse          NSenterMsgType = "mountInfoResponse"
	MountInodeRequest          NSenterMsgType = "mountInodeRequest"
	MountInodeResponse         NSenterMsgType = "mountInodeResponse"
	SleepRequest               NSenterMsgType = "sleepRequest"
	SleepResponse              NSenterMsgType = "sleepResponse"
	SetxattrSyscallRequest     NSenterMsgType = "setxattrSyscallRequest"
	SetxattrSyscallResponse    NSenterMsgType = "setxattrSyscallResponse"
	GetxattrSyscallRequest     NSenterMsgType = "getxattrSyscallRequest"
	GetxattrSyscallResponse    NSenterMsgType = "getxattrSyscallResponse"
	RemovexattrSyscallRequest  NSenterMsgType = "RemovexattrSyscallRequest"
	RemovexattrSyscallResponse NSenterMsgType = "RemovexattrSyscallResponse"
	ListxattrSyscallRequest    NSenterMsgType = "ListxattrSyscallRequest"
	ListxattrSyscallResponse   NSenterMsgType = "ListxattrSyscallResponse"
	UidInfoRequest             NSenterMsgType = "uidInfoRequest"
	UidInfoResponse            NSenterMsgType = "uidInfoResponse"
	GidInfoRequest             NSenterMsgType = "gidInfoRequest"
	GidInfoResponse            NSenterMsgType = "gidInfoResponse"
	Openat2SyscallRequest      NSenterMsgType = "openat2SyscallRequest"
	Openat2SyscallResponse     NSenterMsgType = "openat2SyscallResponse"
	ErrorResponse              NSenterMsgType = "errorResponse"
)

// NSenterService interface serves as a wrapper construct to provide a
// communication channel between sysbox-fs 'master' and sysbox-fs 'child'
// entities. See more details further below.
type NSenterServiceIface interface {
	NewEvent(
		pid uint32,
		uid uint32,
		gid uint32,
		ns *[]NStype,
		cloneFlags uint32,
		req *NSenterMessage,
		res *NSenterMessage,
		async bool) NSenterEventIface

	Setup(prs ProcessServiceIface, mts MountServiceIface)
	SendRequestEvent(e NSenterEventIface) error
	ReceiveResponseEvent(e NSenterEventIface) *NSenterMessage
	TerminateRequestEvent(e NSenterEventIface) error
	GetEventProcessID(e NSenterEventIface) uint32
}

// NSenterEvent struct serves as a transport abstraction (envelope) to carry
// all the potential messages that can be exchanged between sysbox-fs master
// instance and secondary (forked) ones. These sysbox-fs' auxiliary instances
// are utilized to perform actions over namespaced resources, and as such,
// cannot be executed by sysbox-fs' main instance.
//
// Every bidirectional transaction is represented by an event structure
// (nsenterEvent), which holds both 'request' and 'response' messages, as well
// as the context necessary to complete any action demanding inter-namespace
// message exchanges.
type NSenterEventIface interface {
	SendRequest() error
	TerminateRequest() error
	ReceiveResponse() *NSenterMessage
	SetRequestMsg(m *NSenterMessage)
	GetRequestMsg() *NSenterMessage
	SetResponseMsg(m *NSenterMessage)
	GetResponseMsg() *NSenterMessage
	GetProcessID() uint32
}

// NSenterMessage struct defines the layout of the messages being exchanged
// between sysbox-fs 'main' and 'forked' ones.
type NSenterMessage struct {
	// Message type being exchanged.
	Type NSenterMsgType `json:"message"`

	// Message payload.
	Payload interface{} `json:"payload"`
}

type NSenterMsgHeader struct {
	// Note: pid, uid, and gid, and file descriptors are sent apart via socket control messages (SCM) creds/rights.
	// This way the kernel automatically translates them across process namespaces (e.g., from sysbox-fs to the nsenter
	// process namespaces for nsenter requests, or vice-versa for nsenter responses).
	Root         string    `json:"root"`
	Cwd          string    `json:"cwd"`
	Capabilities [2]uint32 `json:"capabilities"`
}

type LookupPayload struct {
	Entry       string `json:"entry"`
	MountSysfs  bool   `json:mountSysfs`
	MountProcfs bool   `json:mountProcfs`
}

type OpenFilePayload struct {
	File        string `json:"file"`
	Flags       string `json:"flags"`
	Mode        string `json:"mode"`
	MountSysfs  bool   `json:mountSysfs`
	MountProcfs bool   `json:mountProcfs`
}

type ReadFilePayload struct {
	File        string `json:"file"`
	Offset      int64  `json:"offset"`
	Len         int    `json:"len"`
	MountSysfs  bool   `json:mountSysfs`
	MountProcfs bool   `json:mountProcfs`
}

type WriteFilePayload struct {
	File        string `json:"file"`
	Offset      int64  `json:"offset"`
	Data        []byte `json:"data"`
	MountSysfs  bool   `json:mountSysfs`
	MountProcfs bool   `json:mountProcfs`
}

type ReadDirPayload struct {
	Dir         string `json:"dir"`
	MountSysfs  bool   `json:mountSysfs`
	MountProcfs bool   `json:mountProcfs`
}

type ReadLinkPayload struct {
	Link        string `json:"link"`
	MountSysfs  bool   `json:mountSysfs`
	MountProcfs bool   `json:mountProcfs`
}

type MountSyscallPayload struct {
	Header NSenterMsgHeader
	Mount
}

type UmountSyscallPayload struct {
	Header NSenterMsgHeader
	Mount
}

type ChownSyscallPayload struct {
	Target    string `json:"target"`
	TargetUid int    `json:"uid"`
	TargetGid int    `json:"gid"`
}

type SetxattrSyscallPayload struct {
	Syscall string `json:"syscall"`
	Path    string `json:"path"`
	Name    string `json:"name"`
	Val     []byte `json:"val"`
	Flags   int    `json:"flags"`
}

type GetxattrSyscallPayload struct {
	Header  NSenterMsgHeader
	Syscall string `json:"syscall"`
	Path    string `json:"path"`
	Name    string `json:"name"`
	Size    uint64 `json:"size"`
}

type GetxattrRespPayload struct {
	Val  []byte `json:"val"`
	Size int    `json:"size"`
}

type RemovexattrSyscallPayload struct {
	Syscall string `json:"syscall"`
	Path    string `json:"path"`
	Name    string `json:"name"`
}

type ListxattrSyscallPayload struct {
	Header  NSenterMsgHeader
	Syscall string `json:"syscall"`
	Path    string `json:"path"`
	Size    uint64 `json:"size"`
}

type ListxattrRespPayload struct {
	Val  []byte `json:"val"`
	Size int    `json:"size"`
}

type MountInfoRespPayload struct {
	Data []byte `json:"data"`
}

type MountInodeReqPayload struct {
	Mountpoints []string `json:"mountpoints"`
}
type MountInodeRespPayload struct {
	MpInodes []Inode `json:"mpinodes"`
}

type SleepReqPayload struct {
	Ival string `json:"attr"`
}

type UidInfoReqPayload struct {
	User string `json:"user"`
}

type UidInfoRespPayload struct {
	Uid string `json:"uid"`
}

type GidInfoReqPayload struct {
	Group string `json:"group"`
}

type GidInfoRespPayload struct {
	Gid string `json:"gid"`
}

type Openat2SyscallPayload struct {
	Header  NSenterMsgHeader `json:"header"`
	Path    string           `json:"path"`
	Flags   uint64           `json:"flags"`
	Mode    uint64           `json:"mode"`
	Resolve uint64           `json:"resolve"`
}

type Openat2RespPayload struct {
	Fd int `json:"fd"`
}
