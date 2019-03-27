package main

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
type nsenterEventType = string

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
	readRequest   nsenterEventType = "readRequest"
	readResponse  nsenterEventType = "readResponse"
	writeRequest  nsenterEventType = "writeRequest"
	writeResponse nsenterEventType = "writeResponse"
	errorResponse nsenterEventType = "errorResponse"
)

//
// nsenterEvent struct serves as a transport abstraction to represent all the
// potential messages that can be exchanged between sysvisor-fs master instance
// and secondary (forked) ones. These sysvisor-fs' auxiliar instances are
// utilized to carry out actions over namespaced resources, and as such, cannot
// be performed by sysvisor-fs' main instance.
//
// Every transaction is represented by an event structure (nsenterEvent), which
// holds all the elements, as well as the context, necessary to complete any
// action demanding inter-namespace message exchanges.
//
type nsenterEvent struct {

	// File/Dir being accessed within a container context.
	Resource string `json:"resource"`

	// Message type being exchanged.
	Message nsenterEventType `json:"message"`

	// Content/payload of the message.
	Content string `json:"content"`

	// initPid associated to the targeted container.
	Pid uint32 `json:"pid"`

	// namespace-types to attach to.
	Namespace []nsType `json:"namespace"`
}

func (e *nsenterEvent) processWriteRequest() (*nsenterEvent, error) {

	err := ioutil.WriteFile(e.Resource, []byte(e.Content), 0644)
	if err != nil {
		log.Printf("Error writing to %s resource", e.Resource)
		return &nsenterEvent{Message: errorResponse, Content: err.Error()}, nil
	}

	return &nsenterEvent{Message: writeResponse}, nil
}

func (e *nsenterEvent) processReadRequest() (*nsenterEvent, error) {

	fileContent, err := ioutil.ReadFile(e.Resource)
	if err != nil {
		log.Printf("Error reading from %s resource", e.Resource)
		return &nsenterEvent{Message: errorResponse, Content: err.Error()}, nil
	}

	res := &nsenterEvent{
		Message: readResponse,
		Content: strings.TrimSpace(string(fileContent)),
	}

	return res, nil
}

func (e *nsenterEvent) processRequest(pipe io.Reader) (*nsenterEvent, error) {

	var event nsenterEvent

	if err := json.NewDecoder(pipe).Decode(&event); err != nil {
		return nil, errors.New("Error decoding received nsenterEvent request")
	}

	switch event.Message {
	case readRequest:
		return event.processReadRequest()
	case writeRequest:
		return event.processWriteRequest()
	default:
		event.Message = errorResponse
		event.Content = "Unsupported request"
	}

	return &event, nil
}

//
// Invoked by sysvisor-fs handler routines to parse the response generated
// by sysvisor-fs' grand-child processes.
//
func (e *nsenterEvent) processResponse(pipe io.Reader) (*nsenterEvent, error) {

	var event nsenterEvent

	dec := json.NewDecoder(pipe)

	if err := dec.Decode(&event); err != nil {
		log.Println("Error decoding received nsenterEvent reponse")
		return nil, errors.New("Error decoding received event response")
	}

	// Log received message for debugging purposes.
	switch event.Message {
	case readResponse:
		log.Println("Received nsenterEvent readResponse message")
		break
	case writeResponse:
		log.Println("Received nsenterEvent writeResponse message")
		break
	case errorResponse:
		log.Println("Received nsenterEvent errorResponse message:", event.Content)
		break
	default:
		return nil, errors.New("Received unsupported nsenterEvent message")
	}

	return &event, nil
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
func (e *nsenterEvent) launch() (*nsenterEvent, error) {

	log.Println("Executing nsenterEvent's launch() method")

	// Create a socket pair.
	parentPipe, childPipe, err := utils.NewSockPair("nsenterPipe")
	if err != nil {
		return nil, errors.New("Error creating sysvisor-fs nsenter pipe")
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
		return nil, errors.New("Error launching sysvisor-fs first child process")
	}

	// Send the config to child process.
	if _, err := io.Copy(parentPipe, bytes.NewReader(r.Serialize())); err != nil {
		return nil, errors.New("Error copying payload to pipe")
	}

	// Wait for sysvisor-fs' first child process to finish.
	status, err := cmd.Process.Wait()
	if err != nil {
		cmd.Wait()
		return nil, err
	}
	if !status.Success() {
		cmd.Wait()
		return nil, errors.New("Error waiting for sysvisor-fs first child process")
	}

	// Receive sysvisor-fs' first-child pid.
	var pid pid
	decoder := json.NewDecoder(parentPipe)
	if err := decoder.Decode(&pid); err != nil {
		cmd.Wait()
		return nil, errors.New("Error receiving first-child pid")
	}

	firstChildProcess, err := os.FindProcess(pid.PidFirstChild)
	if err != nil {
		return nil, err
	}

	// Wait for sysvisor-fs' second child process to finish. Ignore the error in
	// case the child has already been reaped for any reason.
	_, _ = firstChildProcess.Wait()

	// Sysvisor-fs' third child (grand-child) process remains and will enter the
	// go runtime.
	process, err := os.FindProcess(pid.Pid)
	if err != nil {
		return nil, err
	}
	cmd.Process = process

	// Transfer the nsenterEvent details to grand-child for processing.
	if err := utils.WriteJSON(parentPipe, e); err != nil {
		return nil, errors.New("Error writing nsenterEvent through pipe")
	}

	// Wait for sysvisor-fs' grand-child response and process it accordingly.
	res, ierr := e.processResponse(parentPipe)

	// Destroy the socket pair.
	if err := unix.Shutdown(int(parentPipe.Fd()), unix.SHUT_WR); err != nil {
		return nil, errors.New("Shutting down sysvisor-fs nsenter pipe")
	}

	if ierr != nil {
		cmd.Wait()
		return nil, ierr
	}

	// Wait for grand-child exit()
	cmd.Wait()

	return res, nil
}

//
// Sysvisor-fs' post-nsexec initialization function. To be executed within the
// context of one (or more) container namespaces.
//
func nsenter() (err error) {

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
	res, err := event.processRequest(pipe)
	if err != nil {
		return err
	}

	_ = utils.WriteJSON(pipe, res)

	return nil
}
