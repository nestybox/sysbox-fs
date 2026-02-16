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
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

type Server struct {
	listener net.UnixListener
	handler  func(*net.UnixConn)
}

// NewServer constructs a unix-server to handle inbound connections made to the
// 'addr' unix-socket. Upon establishment, the connection will be handled by the
// 'func' closure passed as parameter.
func NewServer(addr string, handler func(*net.UnixConn)) (*Server, error) {

	if err := os.RemoveAll(addr); err != nil {
		logrus.Errorf("Unable to remove address %v (%v).", addr, err)
		return nil, err
	}

	if err := os.MkdirAll(path.Dir(addr), 0700); err != nil {
		logrus.Errorf("Unable to mkdir %v (%v).", path.Dir(addr), err)
		return nil, err
	}

	unixAddr, err := net.ResolveUnixAddr("unix", addr)
	if err != nil {
		logrus.Errorf("Unable to resolve address %v (%v).", addr, err)
		return nil, err
	}

	listener, err := net.ListenUnix("unix", unixAddr)
	if err != nil {
		logrus.Errorf("Unable to listen through addr %v (%v).", addr, err)
		return nil, err
	}

	err = os.Chmod(addr, 0600)
	if err != nil {
		logrus.Errorf("Unable to set %v socket permissions (%v).", addr, err)
		return nil, err
	}

	srv := &Server{
		listener: *listener,
		handler:  handler,
	}

	go srv.run()

	return srv, nil
}

func (s *Server) run() {

	// TODO: Handler stop-signals from main() thread.
	for {
		conn, err := s.listener.AcceptUnix()
		if err != nil {
			logrus.Errorf("Unable to establish connection (%v).", err)
			return
		}

		go s.handler(conn)
	}
}

func Connect(addr string) (*net.UnixConn, error) {

	unixAddr, err := net.ResolveUnixAddr("unix", addr)
	if err != nil {
		logrus.Errorf("Unable to resolve address %v (%v).", addr, err)
		return nil, err
	}

	conn, err := net.DialUnix("unix", nil, unixAddr)
	if err != nil {
		logrus.Errorf("Unable to dial to addr %v (%v).", addr, err)
		return nil, err
	}

	return conn, nil
}

type seccompInit struct {
	Pid    int32  `json:"pid"`
	CntrId string `json:"cntrId"`
}

func RecvSeccompInitMsg(c *net.UnixConn) (int32, string, int32, error) {

	// TODO: Define these literals in a proper location.
	// {"pid": 27693,"cntrId":"54970eb2fa086ccd0f550b23679d13fc577e041be14121d78d9389ec051b20f8"}
	const inbLength = 100 // 4 bytes pid + 64 bytes cntrId + padding
	var oobLength = unix.CmsgSpace(4)

	inb := make([]byte, inbLength)
	oob := make([]byte, oobLength)

	if err := recvGenericMsg(c, inb, oob); err != nil {
		return -1, "", -1, err
	}

	// Parse received control-msg to extract one file-descriptor.
	fd, err := parseScmRightsFd(c, oob)
	if err != nil {
		return -1, "", -1, err
	}

	// Remove any null character that may have come along.
	payload := bytes.TrimRight(inb, "\x00")

	// Decode inband payload msg.
	var seccompInit seccompInit
	err = json.Unmarshal(payload, &seccompInit)
	if err != nil {
		return -1, "", -1, err
	}

	return seccompInit.Pid, seccompInit.CntrId, fd, nil
}

func SendSeccompInitMsg(
	c *net.UnixConn, pid int32, cntrId string, fd int32) error {

	// Construct scm message.
	oob := unix.UnixRights(int(fd))

	seccompInit := &seccompInit{Pid: pid, CntrId: cntrId}
	inb, err := json.Marshal(seccompInit)
	if err != nil {
		logrus.Errorf("Could not encode seccompInit payload (%v)", err)
		return err
	}

	// Send payload + scm messages.
	err = sendGenericMsg(c, inb, oob)
	if err != nil {
		return err
	}

	return nil
}

func RecvSeccompInitAckMsg(c *net.UnixConn) error {

	buf := make([]byte, 3)

	// Send payload.
	err := recvGenericMsg(c, buf, nil)
	if err != nil {
		return err
	}

	if string(buf) != "ack" {
		return fmt.Errorf("invalid ack: %v", buf)
	}

	return nil
}

func SendSeccompInitAckMsg(c *net.UnixConn) error {

	// Send payload.
	err := sendGenericMsg(c, []byte("ack"), nil)
	if err != nil {
		return err
	}

	return nil
}

func recvGenericMsg(c *net.UnixConn, inb []byte, oob []byte) error {

	inbSize := len(inb)
	oobSize := len(oob)

	inbn, oobn, _, _, err := c.ReadMsgUnix(inb, oob)
	if err != nil {
		logrus.Errorf("Unable to read message from endpoint %v (%v).",
			c.RemoteAddr(), err)
		return err
	}

	if inbn > inbSize || oobn > oobSize {
		logrus.Errorf("Invalid msg received from endpoint %v", c.RemoteAddr())
		return err
	}

	// Truncate inband and outbound buffers to match received sizes.
	inb = inb[:inbn]
	oob = oob[:oobn]

	return nil
}

func sendGenericMsg(c *net.UnixConn, inb []byte, oob []byte) error {

	inbSize := len(inb)
	oobSize := len(oob)

	inbn, oobn, err := c.WriteMsgUnix(inb, oob, nil)
	if err != nil {
		logrus.Errorf("Unable to write message to endpoint %v", c.RemoteAddr())
		return err
	}

	if inbn < inbSize || oobn < oobSize {
		logrus.Errorf("Invalid msg sent to endpoint %v", c.RemoteAddr())
		return err
	}

	return nil
}

func parseScmRightsFd(c *net.UnixConn, oob []byte) (int32, error) {

	scms, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		logrus.Errorf("Unexpected error while parsing SocketControlMessage msg")
		return 0, err
	}
	if len(scms) != 1 {
		logrus.Errorf("Unexpected number of SocketControlMessages received: expected 1, received %v",
			len(scms))
		return -1, err
	}

	fds, err := unix.ParseUnixRights(&scms[0])
	if err != nil {
		return -1, err
	}
	if len(fds) != 1 {
		return -1, fmt.Errorf("Unexpected number of fd's received: expected 1, received %v",
			len(fds))
	}
	fd := int32(fds[0])

	return fd, nil
}
