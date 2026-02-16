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

package unix

import (
	"fmt"
	"os"
	"sync"
	"syscall"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

//
// The following PollServer implementation offers non-blocking I/O capabilities
// to applications that interact with generic file-descriptors. For network
// specific I/O there are known implementations providing similar functionality.
//
// The following API is offered as part of this PollServer implementation:
//
// StartWaitRead(): Place caller goroutine in 'standby' mode till incoming
// traffic is detected over the respective file-descriptor (POLLIN revent
// received).
//
// StartWaitWrite(): Place caller goroutine in 'standby' mode till outgoing
// traffic can be sent through the respective file-descriptor (POLLOUT revent
// received).
//
// StopWait(): Interrupts pollserver event-loop to update the list of file
// descriptors to poll on. This 'interruption' process relies on the use of a
// unidirectional pipe whose receiving-end is being added to the list of file
// descriptors to monitor. This voids the need to define an explicit 'timeout'
// interval during polling attempts.
//

type pollActionType uint8

const (
	CREATE_POLL_REQUEST pollActionType = iota
	DELETE_POLL_REQUEST
)

// Defines the poll action to execute for a given file-descriptor. Each
// poll-server client allocates one of these objects to interact with the
// poll-server.
type pollAction struct {

	// File-descriptor to poll().
	fd int32

	// Action the poll-server client is interested on: 'addition' or 'deletion'
	// of the fd into/from the poll-event loop.
	actionType pollActionType

	// Channel on which the poll-server client waits during read-request
	// operations.
	waitReadCh chan error

	// Channel on which the poll-server client waits during write-request
	// operations.
	waitWriteCh chan error

	// Channel on which the poll-server client waits for fds to be
	// completely eliminated from the pollServer event-loop.
	waitCloseCh chan error
}

func newPollAction(fd int32, action pollActionType) *pollAction {
	return &pollAction{
		fd:          fd,
		actionType:  action,
		waitReadCh:  make(chan error),
		waitWriteCh: make(chan error),
		waitCloseCh: make(chan error),
	}
}

// General pollserver struct.
type PollServer struct {
	sync.RWMutex

	// 'fd' to 'pollAction' map. This map holds one pollAction per poll-server
	// client.
	pollActionMap map[int32]*pollAction

	// Buffered channel through which pollActions arrive.
	pollActionCh chan *pollAction

	// Wake-up pipe -- writing end
	wakeupReader *os.File

	// Wake-up pipe -- receiving end
	wakeupWriter *os.File
}

func NewPollServer() (*PollServer, error) {
	var err error

	// PollServer struct initialization. Notice that pollActionCh must be buffered
	// to allow incoming pollActions to be injected by pollserver clients *before*
	// the wakeup signal interrupts the polling cycle (see comments below as part
	// of pushPollAction method).
	ps := &PollServer{
		pollActionMap: make(map[int32]*pollAction),
		pollActionCh:  make(chan *pollAction, 1),
	}

	// Initialize pollserver's wakeup pipe.
	ps.wakeupReader, ps.wakeupWriter, err = os.Pipe()
	if err != nil {
		logrus.Errorf("Unable to initialize wakeup pipe in pollserver (%v)", err)
		return nil, err
	}

	// Add wakeup pipe's received-end to the map of fds to monitor.
	ps.pollActionMap[int32(ps.wakeupReader.Fd())] = nil

	go ps.run()

	return ps, nil
}

func (ps *PollServer) StartWaitRead(fd int32) error {

	ps.RLock()
	_, ok := ps.pollActionMap[fd]
	if ok {
		ps.RUnlock()
		return fmt.Errorf("Unexpected fd %d found in pollServer DB", fd)
	}
	ps.RUnlock()

	pa := newPollAction(fd, CREATE_POLL_REQUEST)

	if err := ps.pushPollAction(pa); err != nil {
		return err
	}

	// Block till a POLLIN event (or any POLL-error) is received for this fd.
	err := <-pa.waitReadCh

	return err
}

func (ps *PollServer) StartWaitWrite(fd int32) error {

	ps.RLock()
	_, ok := ps.pollActionMap[fd]
	if ok {
		ps.RUnlock()
		return fmt.Errorf("Unexpected fd %d found in pollServer DB", fd)
	}
	ps.RUnlock()

	pa := newPollAction(fd, CREATE_POLL_REQUEST)

	if err := ps.pushPollAction(pa); err != nil {
		return err
	}

	// Block till a POLLOUT event (or any POLL-error) is received for this fd.
	err := <-pa.waitWriteCh

	return err
}

func (ps *PollServer) StopWait(fd int32) error {

	// We are making a write operation below over the shared pollAction object,
	// so let's acquire the write lock in this case.
	ps.Lock()
	pa, ok := ps.pollActionMap[fd]
	if !ok {
		ps.Unlock()
		return nil
	}

	// Re-tag the existing pollAction as a "delete" one, so that the pollServer
	// client that's currently waiting on the associated fd, can now wakeup from
	// its nap.
	pa.actionType = DELETE_POLL_REQUEST
	ps.Unlock()

	if err := ps.pushPollAction(pa); err != nil {
		return err
	}

	// Wait for an ack from the pollServer's event-loop to confirm that the
	// "delete" has been fully processed.
	err := <-pa.waitCloseCh

	return err
}

// Runs pollserver event-loop.
func (ps *PollServer) run() {

	for {
		// Build file-descriptor slice out of the map that tracks all the polling
		// actions to process. No need to acquire rlock here as this is the very
		// goroutine (and the only one) that modifies pollServer internal structs.
		i := 0
		ps.RLock()
		pfds := make([]unix.PollFd, len(ps.pollActionMap))
		for k := range ps.pollActionMap {
			pfds[i].Fd = k
			pfds[i].Events = unix.POLLIN
			i++
		}
		ps.RUnlock()

		// Initiating polling attempt. Notice that no timeout interval is passed.
		n, err := unix.Poll(pfds, -1)
		if err != nil && err != syscall.EINTR {
			logrus.Debugf("pollserver: error during poll() syscall (%v)", err)
			break
		}
		if n <= 0 {
			logrus.Debugf("pollserver: unexpected value (n = %d) during poll() syscall", n)
			continue
		}

		// Iterate through all fds to evaluate i/o activity.
		for _, pfd := range pfds {

			if pfd.Revents&(unix.POLLHUP|unix.POLLNVAL|unix.POLLERR) != 0 {
				if pfd.Revents&unix.POLLHUP == unix.POLLHUP {
					ps.processPollHupEvent(&pfd)
				}
				if pfd.Revents&unix.POLLNVAL == unix.POLLNVAL {
					ps.processPollNvalEvent(&pfd)
				}
				if pfd.Revents&unix.POLLERR == unix.POLLERR {
					ps.processPollErrEvent(&pfd)
				}

			} else if pfd.Revents&unix.POLLIN == unix.POLLIN {
				if pfd.Fd == int32(ps.wakeupReader.Fd()) {
					ps.processPollWakeupEvent(&pfd)
					continue
				}
				ps.processPollInEvent(&pfd)

			} else if pfd.Revents&unix.POLLOUT == unix.POLLOUT {
				ps.processPollOutEvent(&pfd)
			}
		}
	}
}

// Processes 'pollhup' events received through one of the monitored fds.
func (ps *PollServer) processPollHupEvent(pfd *unix.PollFd) error {

	logrus.Debugf("pollserver: POLLHUP event received on fd %d", pfd.Fd)

	ps.Lock()
	pa, ok := ps.pollActionMap[pfd.Fd]
	if !ok {
		ps.Unlock()
		return fmt.Errorf("pollserver: POLLHUP event received on unknown fd %v",
			pfd.Fd)
	}

	// Delete fd from pollAction map.
	delete(ps.pollActionMap, pfd.Fd)
	ps.Unlock()

	// Wake-up pollserver client.
	pa.waitReadCh <- fmt.Errorf("PollHup event received")

	return nil
}

// Processes 'pollnval' events received through one of the monitored fds.
func (ps *PollServer) processPollNvalEvent(pfd *unix.PollFd) error {

	logrus.Debugf("pollserver: POLLNVAL event received on fd %d", pfd.Fd)

	ps.Lock()
	pa, ok := ps.pollActionMap[pfd.Fd]
	if !ok {
		ps.Unlock()
		return fmt.Errorf("pollserver: POLLNVAL event received on unknown fd %v",
			pfd.Fd)
	}

	// Delete fd from pollAction map.
	delete(ps.pollActionMap, pfd.Fd)
	ps.Unlock()

	// Wake-up pollserver client.
	pa.waitReadCh <- fmt.Errorf("PollNval event received")

	return nil
}

// Processes 'pollErr' events received through one of the monitored fds.
func (ps *PollServer) processPollErrEvent(pfd *unix.PollFd) error {

	logrus.Debugf("pollserver: POLLERR event received on fd %d", pfd.Fd)

	ps.Lock()
	pa, ok := ps.pollActionMap[pfd.Fd]
	if !ok {
		ps.Unlock()
		return fmt.Errorf("pollserver: POLLERR event received on unknown fd %v",
			pfd.Fd)
	}

	// Delete fd from pollAction map.
	delete(ps.pollActionMap, pfd.Fd)
	ps.Unlock()

	// Wake-up pollserver client.
	pa.waitReadCh <- fmt.Errorf("PollErr event received")

	return nil
}

// Processes out-of-band 'wakeup' events generated by pollserver clients.
func (ps *PollServer) processPollWakeupEvent(pfd *unix.PollFd) error {

	logrus.Debugf("pollserver: WAKEUP event received on fd %d", pfd.Fd)

	// TODO: Define this literal in a global var and document its rationale.
	buf := make([]byte, 100)
	_, err := ps.wakeupReader.Read(buf)
	if err != nil {
		logrus.Errorf("processPollWakeupEvent read error (%v)", err)
		return fmt.Errorf("processPollWakeupEvent read error (%v)", err)
	}

	// Collect received pollAction and add it to the pollActionMap
	pa := <-ps.pollActionCh

	switch pa.actionType {

	case CREATE_POLL_REQUEST:
		ps.Lock()
		ps.pollActionMap[pa.fd] = pa
		ps.Unlock()

	case DELETE_POLL_REQUEST:
		ps.Lock()
		oldPa, ok := ps.pollActionMap[pa.fd]
		if !ok {
			ps.Unlock()
			return fmt.Errorf("Could not find pollAction to delete for fd %d", pa.fd)
		}
		delete(ps.pollActionMap, pa.fd)
		ps.Unlock()

		// Send an error back to the pollserver client to wake him up from his
		// nap.
		closedFdError := fmt.Errorf("Interrupted poll operation: closed file-descriptor")
		oldPa.waitReadCh <- closedFdError

		oldPa.waitCloseCh <- nil
	}

	return nil
}

// Processes 'pollin' events received through one of the monitored fds.
func (ps *PollServer) processPollInEvent(pfd *unix.PollFd) error {

	logrus.Debugf("pollserver: POLLIN event received on fd %d", pfd.Fd)

	ps.Lock()
	pa, ok := ps.pollActionMap[pfd.Fd]
	if !ok {
		ps.Unlock()
		return fmt.Errorf("pollserver: POLLIN event received on unknown fd %v",
			pfd.Fd)
	}

	// Delete fd from pollAction map.
	delete(ps.pollActionMap, pfd.Fd)
	ps.Unlock()

	// Wake-up pollserver client.
	pa.waitReadCh <- nil

	return nil
}

// Processes 'pollout' events received through one of the monitored fds.
func (ps *PollServer) processPollOutEvent(pfd *unix.PollFd) error {

	logrus.Debugf("pollserver: POLLOUT event received on fd %d", pfd.Fd)

	ps.Lock()
	pa, ok := ps.pollActionMap[pfd.Fd]
	if !ok {
		ps.Unlock()
		return fmt.Errorf("pollserver: POLLOUT event received on unknown fd %v",
			pfd.Fd)
	}

	// Delete fd from action map.
	delete(ps.pollActionMap, pfd.Fd)
	ps.Unlock()

	// Wakeup pollserver client.
	pa.waitReadCh <- nil

	return nil
}

// Method pushes incoming pollActions into the pollserver's event-loop. Notice
// that the order of instructions in this method is critical: we must first
// send the pollAction, and then proceed to generate the wakeup signal. If we
// were to invert the order, no incoming state (pollAction) could have been
// received by the time that the pollserver awakes, which would end up with
// the pollserver going back to sleep right before the pollAction arrives.
func (ps *PollServer) pushPollAction(pa *pollAction) error {

	ps.pollActionCh <- pa

	// Write into pollserver's wakeupWriter end to interrupt poll() event loop.
	var buf [1]byte
	ps.wakeupWriter.Write(buf[0:])

	return nil
}
