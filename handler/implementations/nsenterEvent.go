package implementations

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/opencontainers/runc/libcontainer"
	_ "github.com/opencontainers/runc/libcontainer/nsenter"
	"github.com/opencontainers/runc/libcontainer/utils"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

func init() {
	if len(os.Args) > 1 && os.Args[1] == "nsenter" {
		runtime.GOMAXPROCS(1)
		runtime.LockOSThread()
	}
}

// Aliases to leverage strong-typing.
type nsType = string
type nsenterMsgType = string

// nsType defines all namespace types
const (
	nsTypeCgroup nsType = "cgroup"
	nsTypeIpc    nsType = "ipc"
	nsTypeNet    nsType = "net"
	nsTypePid    nsType = "pid"
	nsTypeUts    nsType = "uts"
)

// Pid struct. Utilized by sysvisor-runc's nsexec code.
type pid struct {
	Pid           int `json:"pid"`
	PidFirstChild int `json:"pid_first"`
}

//
// nsenterEvent types. Define all possible messages that can be hndled
// by nsenterEvent class.
//
const (
	readFileRequest   nsenterMsgType = "readFileRequest"
	readFileResponse  nsenterMsgType = "readFileResponse"
	writeFileRequest  nsenterMsgType = "writeFileRequest"
	writeFileResponse nsenterMsgType = "writeFileResponse"
	readDirRequest    nsenterMsgType = "readDirRequest"
	readDirResponse   nsenterMsgType = "readDirResponse"
	errorResponse     nsenterMsgType = "errorResponse"
)

type nsenterMessage struct {
	// Message type being exchanged.
	Type nsenterMsgType `json:"message"`

	// Message payload.
	Payload interface{} `json:"payload"`
}

type nsenterDir struct {
	Dname    string
	Dsize    int64
	Dmode    os.FileMode
	DmodTime time.Time
	DisDir   bool
}

func (c nsenterDir) Name() string {
	return c.Dname
}

func (c nsenterDir) Size() int64 {
	return c.Dsize
}

func (c nsenterDir) Mode() os.FileMode {
	return c.Dmode
}

func (c nsenterDir) ModTime() time.Time {
	return c.DmodTime
}

func (c nsenterDir) IsDir() bool {
	return c.DisDir
}

func (c nsenterDir) Sys() interface{} {
	return nil
}

//
// nsenterEvent struct serves as a transport abstraction to represent all the
// potential messages that can be exchanged between sysvisor-fs master instance
// and secondary (forked) ones. These sysvisor-fs' auxiliar instances are
// utilized to carry out actions over namespaced resources, and as such, cannot
// be performed by sysvisor-fs' main instance.
//
// Every bidirectional transaction is represented by an event structure
// (nsenterEvent), which holds both 'request' and 'response' messages, as well
// as the context necessary to complete any action demanding inter-namespace
// message exchanges.
//
type nsenterEvent struct {

	// File/Dir being accessed within a container context.
	Resource string `json:"resource"`

	// initPid associated to the targeted container.
	Pid uint32 `json:"pid"`

	// namespace-types to attach to.
	Namespace []nsType `json:"namespace"`

	// Request message to be sent.
	ReqMsg *nsenterMessage `json:"request"`

	// Request message to be received.
	ResMsg *nsenterMessage `json:"response"`
}

///////////////////////////////////////////////////////////////////////////////
//
// nsenterEvent methods below execute within the context of sysvisor-fs' main
// instance, upon invokation of sysvisor-fs' handler logic.
//
///////////////////////////////////////////////////////////////////////////////

//
// Called by sysvisor-fs handler routines to parse the response generated
// by sysvisor-fs' grand-child processes.
//
func (e *nsenterEvent) processResponse(pipe io.Reader) error {

	//var event nsenterEvent
	var payload json.RawMessage
	nsenterMsg := nsenterMessage{
		Payload: &payload,
	}

	// Read all state received from the incoming pipe.
	data, err := ioutil.ReadAll(pipe)
	if err != nil || data == nil {
		return err
	}

	// Received message will be decoded in two phases. The first unmarshal call
	// takes care of decoding the message-type being received. Based on the
	// obtained type, we are able to decode the polimorphic payload generated
	// by the remote-end. This second step is executed as part of a subsequent
	// unmarshal instruction (further below).
	if err = json.Unmarshal(data, &nsenterMsg); err != nil {
		log.Println("Error decoding received nsenterMsg reponse")
		return errors.New("Error decoding received event response")
	}

	switch nsenterMsg.Type {

	case readFileResponse:
		log.Println("Received nsenterEvent readResponse message")

		var p string
		if err := json.Unmarshal(payload, &p); err != nil {
			log.Fatal(err)
		}

		e.ResMsg = &nsenterMessage{
			Type:    nsenterMsg.Type,
			Payload: p,
		}
		break

	case writeFileResponse:
		log.Println("Received nsenterEvent writeResponse message")
		break

	case readDirResponse:
		log.Println("Received nsenterEvent readDirAllResponse message")

		var p []nsenterDir
		if err := json.Unmarshal(payload, &p); err != nil {
			log.Fatal(err)
		}

		e.ResMsg = &nsenterMessage{
			Type:    nsenterMsg.Type,
			Payload: p,
		}

		break

	case errorResponse:
		log.Println("Received nsenterEvent errorResponse message")
		break

	default:
		return errors.New("Received unsupported nsenterEvent message")
	}

	return nil
}

//
// Auxiliar function to obtain the FS path associated to any given namespace.
// Theese FS paths are utilized by sysvisor-runc's nsexec logic to enter the
// desired namespaces.
//
// Expected format example: "mnt:/proc/<pid>/ns/mnt"
//
func (e *nsenterEvent) namespacePaths() []string {

	var paths []string

	for _, nstype := range e.Namespace {
		path := filepath.Join(
			nstype,
			":/proc/",
			strconv.Itoa(int(e.Pid)), "/ns/",
			nstype)
		paths = append(paths, path)
	}

	return paths
}

//
// Sysvisor-fs' requests are generated through this method. Handlers seeking to
// access namespaced resources will call this method to invoke sysvisor-runc's
// nsexec logic, which will serve to enter the container namespaces that host
// these resources.
//
func (e *nsenterEvent) launch() error {

	log.Println("Executing nsenterEvent's launch() method")

	// Create a socket pair.
	parentPipe, childPipe, err := utils.NewSockPair("nsenterPipe")
	if err != nil {
		return errors.New("Error creating sysvisor-fs nsenter pipe")
	}
	defer parentPipe.Close()

	// Obtain the FS path for all the namespaces to be nsenter'ed into, and
	// define the associated netlink-payload to transfer to child process.
	namespaces := e.namespacePaths()

	r := nl.NewNetlinkRequest(int(libcontainer.InitMsg), 0)
	r.AddData(&libcontainer.Bytemsg{
		Type:  libcontainer.NsPathsAttr,
		Value: []byte(strings.Join(namespaces, ",")),
	})

	// Prepare exec.cmd in charged of running: "sysvisor-fs nsenter".
	cmd := &exec.Cmd{
		Path:       "/proc/self/exe",
		Args:       []string{os.Args[0], "nsenter"},
		ExtraFiles: []*os.File{childPipe},
		Env:        []string{"_LIBCONTAINER_INITPIPE=3", fmt.Sprintf("GOMAXPROCS=%s", os.Getenv("GOMAXPROCS"))},
		Stdin:      nil,
		Stdout:     nil,
		Stderr:     nil,
	}

	// Launch sysvisor-fs' first child process.
	err = cmd.Start()
	childPipe.Close()
	if err != nil {
		return errors.New("Error launching sysvisor-fs first child process")
	}

	// Send the config to child process.
	if _, err := io.Copy(parentPipe, bytes.NewReader(r.Serialize())); err != nil {
		return errors.New("Error copying payload to pipe")
	}

	// Wait for sysvisor-fs' first child process to finish.
	status, err := cmd.Process.Wait()
	if err != nil {
		cmd.Wait()
		return err
	}
	if !status.Success() {
		cmd.Wait()
		return errors.New("Error waiting for sysvisor-fs first child process")
	}

	// Receive sysvisor-fs' first-child pid.
	var pid pid
	decoder := json.NewDecoder(parentPipe)
	if err := decoder.Decode(&pid); err != nil {
		cmd.Wait()
		return errors.New("Error receiving first-child pid")
	}

	firstChildProcess, err := os.FindProcess(pid.PidFirstChild)
	if err != nil {
		return err
	}

	// Wait for sysvisor-fs' second child process to finish. Ignore the error in
	// case the child has already been reaped for any reason.
	_, _ = firstChildProcess.Wait()

	// Sysvisor-fs' third child (grand-child) process remains and will enter the
	// go runtime.
	process, err := os.FindProcess(pid.Pid)
	if err != nil {
		return err
	}
	cmd.Process = process

	// Transfer the nsenterEvent details to grand-child for processing.
	if err := utils.WriteJSON(parentPipe, e); err != nil {
		return errors.New("Error writing nsenterEvent through pipe")
	}

	// Wait for sysvisor-fs' grand-child response and process it accordingly.
	ierr := e.processResponse(parentPipe)

	// Destroy the socket pair.
	if err := unix.Shutdown(int(parentPipe.Fd()), unix.SHUT_WR); err != nil {
		return errors.New("Shutting down sysvisor-fs nsenter pipe")
	}

	if ierr != nil {
		cmd.Wait()
		return ierr
	}

	// Wait for grand-child exit()
	cmd.Wait()

	return nil
}

///////////////////////////////////////////////////////////////////////////////
//
// nsenterEvent methods below execute within the context of container
// namespaces. In other words, they are invoke as part of "sysvisor-fs nsenter"
// execution.
//
///////////////////////////////////////////////////////////////////////////////

func (e *nsenterEvent) processFileWriteRequest() error {

	payload := []byte(e.ReqMsg.Payload.(string))
	err := ioutil.WriteFile(e.Resource, payload, 0644)
	if err != nil {
		log.Printf("Error writing to %s resource", e.Resource)
		e.ResMsg = &nsenterMessage{
			Type:    errorResponse,
			Payload: err.Error(),
		}

		return err
	}

	e.ResMsg = &nsenterMessage{
		Type:    writeFileResponse,
		Payload: nil,
	}

	return nil
}

func (e *nsenterEvent) processFileReadRequest() error {

	fileContent, err := ioutil.ReadFile(e.Resource)
	if err != nil {
		log.Printf("Error reading from %s resource", e.Resource)
		e.ResMsg = &nsenterMessage{
			Type:    errorResponse,
			Payload: err.Error(),
		}

		return err
	}

	e.ResMsg = &nsenterMessage{
		Type:    readFileResponse,
		Payload: strings.TrimSpace(string(fileContent)),
	}

	return nil
}

func (e *nsenterEvent) processDirReadRequest() error {

	dirContent, err := ioutil.ReadDir(e.Resource)
	if err != nil {
		log.Printf("Error reading from %s resource", e.Resource)
		e.ResMsg = &nsenterMessage{
			Type:    errorResponse,
			Payload: err.Error(),
		}

		return err
	}

	var dirContentList []nsenterDir

	for _, entry := range dirContent {
		elem := nsenterDir{
			Dname:    entry.Name(),
			Dsize:    entry.Size(),
			Dmode:    entry.Mode(),
			DmodTime: entry.ModTime(),
			DisDir:   entry.IsDir(),
		}
		dirContentList = append(dirContentList, elem)
	}

	e.ResMsg = &nsenterMessage{
		Type:    readDirResponse,
		Payload: dirContentList,
	}

	return nil
}

// Method in charge of processing  all requests generated by sysvisor-fs master
// instance.
func (e *nsenterEvent) processRequest(pipe io.Reader) error {

	// Decode message into our own nsenterEvent struct.
	if err := json.NewDecoder(pipe).Decode(&e); err != nil {
		return errors.New("Error decoding received nsenterEvent request")
	}

	switch e.ReqMsg.Type {

	case readFileRequest:
		return e.processFileReadRequest()

	case writeFileRequest:
		return e.processFileWriteRequest()

	case readDirRequest:
		return e.processDirReadRequest()

	default:
		e.ResMsg = &nsenterMessage{
			Type:    errorResponse,
			Payload: "Unsupported request",
		}
	}

	return nil
}

//
// Sysvisor-fs' post-nsexec initialization function. To be executed within the
// context of one (or more) container namespaces.
//
func Nsenter() (err error) {

	var (
		pipefd      int
		envInitPipe = os.Getenv("_LIBCONTAINER_INITPIPE")
	)

	// Get the INITPIPE.
	pipefd, err = strconv.Atoi(envInitPipe)
	if err != nil {
		return fmt.Errorf("Unable to convert _LIBCONTAINER_INITPIPE=%s to int: %s",
			envInitPipe, err)
	}

	var pipe = os.NewFile(uintptr(pipefd), "pipe")
	defer pipe.Close()

	// Clear the current process's environment to clean any libcontainer
	// specific env vars.
	os.Clearenv()

	var event nsenterEvent
	err = event.processRequest(pipe)
	if err != nil {
		return err
	}

	_ = utils.WriteJSON(pipe, event.ResMsg)

	return nil
}
