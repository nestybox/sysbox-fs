//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
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

//
// NSenterEvent types. Define all possible messages that can be hndled
// by nsenterEvent class.
//
const (
	LookupRequest        NSenterMsgType = "lookupRequest"
	LookupResponse       NSenterMsgType = "lookupResponse"
	OpenFileRequest      NSenterMsgType = "OpenFileRequest"
	OpenFileResponse     NSenterMsgType = "OpenFileResponse"
	ReadFileRequest      NSenterMsgType = "readFileRequest"
	ReadFileResponse     NSenterMsgType = "readFileResponse"
	WriteFileRequest     NSenterMsgType = "writeFileRequest"
	WriteFileResponse    NSenterMsgType = "writeFileResponse"
	ReadDirRequest       NSenterMsgType = "readDirRequest"
	ReadDirResponse      NSenterMsgType = "readDirResponse"
	MountSyscallRequest  NSenterMsgType = "mountSyscallRequest"
	MountSyscallResponse NSenterMsgType = "mountSyscallResponse"
	ErrorResponse        NSenterMsgType = "errorResponse"
)

//
// NSenterService interface serves as a wrapper construct to provide a
// communication channel between sysbox-fs 'master' and sysbox-fs 'child'
// entities. See more details further below.
//
type NSenterService interface {
	NewEvent(
		pid uint32,
		ns []NStype,
		req *NSenterMessage,
		res *NSenterMessage) NSenterEventIface

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

type OpenFilePayload struct {
	File string `json:"file"`
	Flags string `json:"flags"`
}

type ReadFilePayload struct {
	File    string `json:"file"`
	Content string `json:"content"`
}

type WriteFilePayload struct {
	File    string `json:"file"`
	Content string `json:"content"`
}

type MountSyscallPayload struct {
	Source     string `json:"source"`
	Target     string `json:"target"`
	FsType     string `json:"fstype"`
	Flags      uint64 `json:"flags"`
	Data       string `json:"data"`
}
