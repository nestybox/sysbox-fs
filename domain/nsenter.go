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

var AllNSs = []NStype{
	string(NStypeUser),
	string(NStypePid),
	string(NStypeNet),
	string(NStypeMount),
	string(NStypeIpc),
	string(NStypeCgroup),
	string(NStypeUts),
}

var AllNSsButMount = []NStype{
	string(NStypeUser),
	string(NStypePid),
	string(NStypeNet),
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

//
// NSenterEvent types. Define all possible messages that can be handled
// by nsenterEvent class.
//
const (
	LookupRequest         NSenterMsgType = "lookupRequest"
	LookupResponse        NSenterMsgType = "lookupResponse"
	OpenFileRequest       NSenterMsgType = "OpenFileRequest"
	OpenFileResponse      NSenterMsgType = "OpenFileResponse"
	ReadFileRequest       NSenterMsgType = "readFileRequest"
	ReadFileResponse      NSenterMsgType = "readFileResponse"
	WriteFileRequest      NSenterMsgType = "writeFileRequest"
	WriteFileResponse     NSenterMsgType = "writeFileResponse"
	ReadDirRequest        NSenterMsgType = "readDirRequest"
	ReadDirResponse       NSenterMsgType = "readDirResponse"
	SetAttrRequest        NSenterMsgType = "setAttrRequest"
	SetAttrResponse       NSenterMsgType = "setAttrResponse"
	MountSyscallRequest   NSenterMsgType = "mountSyscallRequest"
	MountSyscallResponse  NSenterMsgType = "mountSyscallResponse"
	UmountSyscallRequest  NSenterMsgType = "umountSyscallRequest"
	UmountSyscallResponse NSenterMsgType = "umountSyscallResponse"
	ChownSyscallRequest   NSenterMsgType = "chownSyscallRequest"
	ChownSyscallResponse  NSenterMsgType = "chownSyscallResponse"
	ErrorResponse         NSenterMsgType = "errorResponse"
)

//
// NSenterService interface serves as a wrapper construct to provide a
// communication channel between sysbox-fs 'master' and sysbox-fs 'child'
// entities. See more details further below.
//
type NSenterServiceIface interface {
	NewEvent(
		pid uint32,
		ns *[]NStype,
		req *NSenterMessage,
		res *NSenterMessage) NSenterEventIface

	Setup(prs ProcessServiceIface)
	SendRequestEvent(e NSenterEventIface) error
	ReceiveResponseEvent(e NSenterEventIface) *NSenterMessage
}

//
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
//
type NSenterEventIface interface {
	SendRequest() error
	ReceiveResponse() *NSenterMessage
	SetRequestMsg(m *NSenterMessage)
	GetRequestMsg() *NSenterMessage
	SetResponseMsg(m *NSenterMessage)
	GetResponseMsg() *NSenterMessage
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
	Pid          uint32    `json:"pid"`
	Uid          uint32    `json:"uid"`
	Gid          uint32    `json:"gid"`
	Root         string    `json:"root"`
	Cwd          string    `json:"cwd"`
	Capabilities [2]uint32 `json:"capabilities"`
}

type LookupPayload struct {
	Entry string `json:"entry"`
}

type OpenFilePayload struct {
	File  string `json:"file"`
	Flags string `json:"flags"`
	Mode  string `json:"mode"`
}

type ReadFilePayload struct {
	File    string `json:"file"`
	Content string `json:"content"`
}

type WriteFilePayload struct {
	File    string `json:"file"`
	Content string `json:"content"`
}

type ReadDirPayload struct {
	Dir string `json:"dir"`
}

type MountSyscallPayload struct {
	Header NSenterMsgHeader
	Source string `json:"source"`
	Target string `json:"target"`
	FsType string `json:"fstype"`
	Flags  uint64 `json:"flags"`
	Data   string `json:"data"`
}

type UmountSyscallPayload struct {
	Header NSenterMsgHeader
	Target string `json:"target"`
	FsType uint8  `json:"-"`
	Flags  uint64 `json:"flags"`
}

type ChownSyscallPayload struct {
	Target string `json:"target"`
	Uid    int    `json:"uid"`
	Gid    int    `json:"gid"`
}
