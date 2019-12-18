package seccomp

import (
	"net"
	//"os"

	"github.com/sirupsen/logrus"
	"github.com/nestybox/sysbox-ipc/unix"
	scmplib "github.com/nestybox/libseccomp-golang"
	"github.com/nestybox/sysbox-fs/domain"
)

const seccompTracerSockAddr = "/run/sysbox/sysfs-seccomp.sock"

type TracerService struct {
	css domain.ContainerStateService
}

func NewTracerService(css domain.ContainerStateService) *TracerService {

	return &TracerService{
		css: css,
	}
}

func (t *TracerService) Init() error {

	// Initialize Tracer Server.
	srv := &unix.Server{}
	if err := srv.Init(seccompTracerSockAddr, t.connHandler); err != nil {
		logrus.Errorf("Unable to initialize seccomp-tracer server")
		return nil
	}

	return nil
}

func (t *TracerService) connHandler(c *net.UnixConn) error {

	logrus.Infof("seccompTracer client connection %v", c.RemoteAddr())

	msg, err := t.RecvMsg(c)
	if err != nil {
		return err
	}

	for {
		//
		req, err := scmplib.NotifReceive(scmplib.ScmpFd(msg.fd))
		if err != nil {
			logrus.Errorf("Unable to receive seccomp-notification request.")
			return err
		}	

		resp, err := t.process(req)
		if err != nil {
			logrus.Errorf("Unable to process seccomp-notification request")
			return err
		}

		err = scmplib.NotifRespond(scmplib.ScmpFd(msg.fd), resp)
		if err != nil {
			logrus.Errorf("Unable to send seccomp-notification response.")
			return err
		}
	}

	return nil
}



func (t *TracerService) process(
	req *scmplib.ScmpNotifReq) (*scmplib.ScmpNotifResp, error) {

	return nil, nil
}

type seccompMsg struct {
	fd int
	cntrId string
}

func (t *TracerService) RecvMsg(c *net.UnixConn) (*seccompMsg, error) {

	fd, cntrId, err := unix.RecvSeccompNotifMsg(c)
	if err != nil {
		logrus.Errorf("Invalid seccomp msg received.")
		return nil, err
	}

	return &seccompMsg{
		fd: fd,
		cntrId: cntrId,
	}, nil
}







	// // Remove seccomp-tracer socket.
	// if err := os.RemoveAll(seccompTracerSockAddr); err != nil {
	// 	logrus.Errorf("Unable to remove() seccompTracer socket.")
	// 	return err
    // }

	// unixAddr, err := net.ResolveUnixAddr("unix", seccompTracerSockAddr)
	// if err != nil {
	// 	logrus.Errorf("Unable to resolve address for seccompTracer socket.")
	// 	return err
	// }

	// // Initialize seccomp-tracer socket.
	// listener, err := net.ListenUnix("unix", unixAddr)
	// if err != nil {
	// 	logrus.Errorf("Unable to listen() through seccompTracer socket.")		
	// 	return err
	// }
	// defer listener.Close()
	
	// for {
	// 	//
	// 	conn, err := listener.AcceptUnix()
	// 	if err != nil {
	// 		logrus.Errorf("Unable to accept() seccompTracer connection.")
	// 		return err
	// 	}

	// 	go t.connectionHandler(conn)
	// }