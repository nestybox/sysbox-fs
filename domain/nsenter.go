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
)

//
// NSenterEvent types. Define all possible messages that can be hndled
// by nsenterEvent class.
//
const (
	LookupRequest     NSenterMsgType = "lookupRequest"
	LookupResponse    NSenterMsgType = "lookupResponse"
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
// communication channel between sysvisor-fs 'master' and sysvisor-fs 'child'
// entities. See more details further below.
//
type NSenterService interface {
	NewEvent(
		path string,
		pid uint32,
		ns []NStype,
		req *NSenterMessage,
		res *NSenterMessage) NSenterEventIface
}

//
// NSenterEvent interface serves as a transport abstraction to represent all
// the potential messages that can be exchanged between sysvisor-fs 'master'
// instance and secondary (forked/child) ones. These sysvisor-fs' auxiliar
// instances are utilized to carry out actions over namespaced resources, and
// as such, cannot be performed by sysvisor-fs' main instance.
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
// between
type NSenterMessage struct {
	// Message type being exchanged.
	Type NSenterMsgType `json:"message"`

	// Message payload.
	Payload interface{} `json:"payload"`
}
