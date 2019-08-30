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
	NStypeMount  NStype = "mount"
)

//
// NSenterEvent types. Define all possible messages that can be hndled
// by nsenterEvent class.
//
const (
	LookupRequest     NSenterMsgType = "lookupRequest"
	LookupResponse    NSenterMsgType = "lookupResponse"
	OpenFileRequest   NSenterMsgType = "OpenFileRequest"
	OpenFileResponse  NSenterMsgType = "OpenFileResponse"
	ReadFileRequest   NSenterMsgType = "readFileRequest"
	ReadFileResponse  NSenterMsgType = "readFileResponse"
	WriteFileRequest  NSenterMsgType = "writeFileRequest"
	WriteFileResponse NSenterMsgType = "writeFileResponse"
	ReadDirRequest    NSenterMsgType = "readDirRequest"
	ReadDirResponse   NSenterMsgType = "readDirResponse"
	ErrorResponse     NSenterMsgType = "errorResponse"
)

//
// NSenterService interface serves as a wrapper construct to provide a
// communication channel between sysbox-fs 'master' and sysbox-fs 'child'
// entities. See more details further below.
//
type NSenterService interface {
	NewEvent(
		path string,
		pid uint32,
		ns []NStype,
		req *NSenterMessage,
		res *NSenterMessage) NSenterEventIface

	LaunchEvent(e NSenterEventIface) error
	ResponseEvent(e NSenterEventIface) *NSenterMessage
}

//
// NSenterEvent interface serves as a transport abstraction to represent all
// the potential messages that can be exchanged between sysbox-fs 'master'
// instance and secondary (forked/child) ones. These sysbox-fs' auxiliary
// instances are utilized to carry out actions over namespaced resources, and
// as such, cannot be performed by sysbox-fs' main instance.
//
// Every bidirectional transaction is represented by an event structure
// (nsenterEvent), which holds both 'request' and 'response' messages, as well
// as the context necessary to complete any action demanding inter-namespace
// message exchanges.
//
type NSenterEventIface interface {
	Launch() error
	Response() *NSenterMessage
}

// NSenterMessage struct defines the layout of the messages being exchanged
// between sysbox-fs 'main' and 'forked' ones.
type NSenterMessage struct {
	// Message type being exchanged.
	Type NSenterMsgType `json:"message"`

	// Message payload.
	Payload interface{} `json:"payload"`
}
