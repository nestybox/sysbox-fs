package seccomp

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/nestybox/sysbox-fs/domain"
	unixIpc "github.com/nestybox/sysbox-ipc/unix"
	"github.com/nestybox/sysbox/lib/pathres"
	"github.com/nestybox/sysbox/lib/pidmonitor"
	libseccomp "github.com/seccomp/libseccomp-golang"
	"github.com/sirupsen/logrus"
	"github.com/syndtr/gocapability/capability"
)

const seccompTracerSockAddr = "/run/sysbox/sysfs-seccomp.sock"

// libseccomp req/resp aliases.
type sysRequest = libseccomp.ScmpNotifReq
type sysResponse = libseccomp.ScmpNotifResp

// Slice of supported syscalls to monitor.
var monitoredSyscalls = []string{
	"mount",
	"umount2",
	"reboot",
	"swapon",
	"swapoff",
}

// Seccomp's syscall-monitoring/trapping service struct. External packages
// will solely rely on this struct for their syscall-monitoring demands.
type SyscallMonitorService struct {
	nss    domain.NSenterService        // for nsenter functionality requirements
	css    domain.ContainerStateService // for container-state interactions
	hns    domain.HandlerService        // for handlerDB interactions
	tracer *syscallTracer               // pointer to actual syscall-tracer instance
}

func NewSyscallMonitorService(
	nss domain.NSenterService,
	css domain.ContainerStateService,
	hns domain.HandlerService) *SyscallMonitorService {

	svc := &SyscallMonitorService{
		nss: nss,
		css: css,
		hns: hns,
	}

	// Allocate a new syscall-tracer.
	svc.tracer = newSyscallTracer(svc)

	// Initialize and launch the syscall-tracer.
	if err := svc.tracer.start(); err != nil {
		return nil
	}

	return svc
}

//
type cmd int

const (
	stop cmd = iota
)

type pidFd struct {
	pid uint32
	fd  int32
}

// Seccomp's syscall-monitor/tracer.
type syscallTracer struct {
	sms         *SyscallMonitorService // backpointer to syscall-monitor service
	srv         *unixIpc.Server        // unix server listening to seccomp-notifs
	pollsrv     *unixIpc.PollServer
	syscalls    map[libseccomp.ScmpSyscall]string // hashmap of supported syscalls indexed by id
	mountHelper *mountHelper                      // generic methods/state utilized for (u)mount ops.
	pidFdCh     chan pidFd
}

func newSyscallTracer(sms *SyscallMonitorService) *syscallTracer {

	tracer := &syscallTracer{
		sms:      sms,
		syscalls: make(map[libseccomp.ScmpSyscall]string),
		pidFdCh:  make(chan pidFd),
	}

	// Populate hashmap of supported syscalls to monitor.
	for _, syscall := range monitoredSyscalls {
		syscallId, err := libseccomp.GetSyscallFromName(syscall)
		if err != nil {
			logrus.Errorf("Seccomp-tracer initialization error: unknown syscall (%v).",
				syscall)
			return nil
		}
		tracer.syscalls[syscallId] = syscall
	}

	// Populate bind-mounts hashmap. Note that handlers are not operating at
	// this point, so there's no need to acquire locks for this operation.
	handlerDB := sms.hns.HandlerDB()
	if handlerDB == nil {
		logrus.Errorf("Seccomp-tracer initialization error: missing handlerDB")
		return nil
	}
	tracer.mountHelper = newMountHelper(handlerDB)

	return tracer
}

// Start syscall tracer.
func (t *syscallTracer) start() error {

	// Enforce proper support of seccomp-monitoring capabilities by the existing
	// kernel; bail otherwise.
	api, err := libseccomp.GetApi()
	if err != nil {
		logrus.Errorf("Error while obtaining seccomp API level (%v).", err)
		return err
	} else if api < 5 {
		logrus.Errorf("Error: need seccomp API level >= 5; it's currently %d", api)
		return fmt.Errorf("Error: unsupported kernel")
	}

	// Launch a new server to listen to seccomp-tracer's socket. Incoming messages
	// will be handled through a separated / dedicated goroutine.
	srv, err := unixIpc.NewServer(seccompTracerSockAddr, t.connHandler)
	if err != nil {
		logrus.Errorf("Unable to initialize seccomp-tracer server")
		return err
	}
	t.srv = srv

	// Launch a new pollServer
	pollsrv, err := unixIpc.NewPollServer()
	if err != nil {
		logrus.Errorf("Unable to initialize seccomp-tracer pollserver")
		return err
	}
	t.pollsrv = pollsrv

	go t.pidMonitor()

	return nil
}

// Launch fd garbage-collection goroutine
// 0) Initialize pidMon logic (with no pid initially)
// 1) Collect / Store seccomp-fds and tracee-pids being in use
// 2) Add tracee-pid to pidMon event-loop
// 3) Upon response from pidMon, proceed to close associated fd
func (t *syscallTracer) pidMonitor() error {

	var pidFdMap = make(map[uint32]pidFd)

	pm, err := pidmonitor.New(&pidmonitor.Cfg{100})
	if err != nil {
		logrus.Error("Could not initialize pidMonitor logic")
		return err
	}
	defer pm.Close()

	for {

		select {
		case elem := <-t.pidFdCh:

			logrus.Errorf("Received pidFd type: %v", elem)

			pidFdMap[elem.pid] = elem
			pm.AddEvent([]pidmonitor.PidEvent{
				pidmonitor.PidEvent{
					Pid:   elem.pid,
					Event: pidmonitor.Exit,
					Err:   nil,
				},
			})

		case pidList := <-pm.EventCh:

			logrus.Errorf("Received waitEvent response: %v", pidList)

			for _, pidEvent := range pidList {
				elem, ok := pidFdMap[pidEvent.Pid]
				if !ok {
					logrus.Errorf("Unexpected error: file-descriptor not found for pid %d",
						pidEvent.Pid)
					continue
				}

				if err := syscall.Close(int(elem.fd)); err != nil {
					logrus.Fatal(err)
				}
				delete(pidFdMap, pidEvent.Pid)

				t.pollsrv.StopWait(elem.fd)
			}
		}
	}

	return nil
}

// Tracer's connection-handler method. Executed within a dedicated goroutine (one
// per connection).
func (t *syscallTracer) connHandler(c *net.UnixConn) error {

	remoteAddr := c.RemoteAddr().Network()

	logrus.Infof("seccompTracer client connection %v", remoteAddr)

	// Obtain seccomp-notification's file-descriptor and associated context (cntr).
	pid, cntrID, fd, err := unixIpc.RecvSeccompInitMsg(c)
	if err != nil {
		return err
	}

	// Obtain container associated to the received containerId value.
	cntr := t.sms.css.ContainerLookupById(cntrID)
	if cntr == nil {
		logrus.Errorf("Received seccompNotifMsg from unknown container: %s", cntrID)
		return fmt.Errorf("Received seccompNotifMsg from unknown container: %s", cntrID)
	}

	// Send pidFd to parent monitor-service for tracking purposes.
	t.pidFdCh <- pidFd{uint32(pid), fd}

	// Send Ack message back to sysbox-runc.
	if err = unixIpc.SendSeccompInitAckMsg(c); err != nil {
		return err
	}

	for {
		// Wait for incoming seccomp-notification msg to be available.
		if err := t.pollsrv.StartWaitRead(fd); err != nil {
			return err
		}

		// Retrieves seccomp-notification message.
		req, err := libseccomp.NotifReceive(libseccomp.ScmpFd(fd))
		if err != nil {
			if err == syscall.EINTR {
				logrus.Errorf("Incomplete NotifReceive() execution (%v). Relaunching ...",
					err)
				continue
			}

			logrus.Errorf("Unexpected error received during NotifReceive() execution (%v).",
				err)
			return err
		}

		// Process the incoming syscall.
		resp, err := t.process(req, fd, cntrID)
		if err != nil {
			logrus.Errorf("Unable to process seccomp-notification request (%v).", err)
			return err
		}

		// Responds to a previously received seccomp-notification.
		err = libseccomp.NotifRespond(libseccomp.ScmpFd(fd), resp)
		if err != nil {
			if err == syscall.EINTR {
				logrus.Errorf("Incomplete NotifRespond() execution (%v). Relaunching ...")
				continue
			}

			logrus.Errorf("Unexpected error received during NotifRespond() execution (%v).",
				err)
			return err
		}
	}

	return nil
}

// Syscall processing entrypoint.
func (t *syscallTracer) process(
	req *sysRequest,
	fd int32,
	cntrID string) (*sysResponse, error) {

	var (
		resp *sysResponse
		err  error
	)

	// Obtain container associated to the received containerId value.
	cntr := t.sms.css.ContainerLookupById(cntrID)
	if cntr == nil {
		logrus.Errorf("Received seccompNotifMsg generated by unknown container: %v",
			cntrID)
		return t.createErrorResponse(req.Id, syscall.EPERM), nil
	}

	syscallId := req.Data.Syscall
	syscall := t.syscalls[syscallId]

	switch syscall {
	case "mount":
		resp, err = t.processMount(req, fd, cntr)

	case "umount2":
		resp, err = t.processUmount(req, fd, cntr)

	case "reboot":
		resp, err = t.processReboot(req, fd, cntr)

	case "swapon":
		resp, err = t.processSwapon(req, fd, cntr)

	case "swapoff":
		resp, err = t.processSwapoff(req, fd, cntr)

	default:
		logrus.Errorf("Unsupported syscall notification received (%v).", syscallId)
		return nil, fmt.Errorf("Unsupported syscall notification")
	}

	if err != nil {
		logrus.Errorf("Error during syscall \"%v\" processing (%v).", syscall, err)
		return nil, err
	}

	// TOCTOU check.
	if err := libseccomp.NotifIdValid(libseccomp.ScmpFd(fd), req.Id); err != nil {
		logrus.Errorf("TOCTOU check failed: req.Id is no longer valid (%s).", err)
		return t.createErrorResponse(req.Id, err), nil
	}

	return resp, err
}

func (t *syscallTracer) processMount(
	req *sysRequest,
	fd int32,
	cntr domain.ContainerIface) (*sysResponse, error) {

	logrus.Debugf("Received mount syscall from pid %d", req.Pid)

	argPtrs := []uint64{
		req.Data.Args[0],
		req.Data.Args[1],
		req.Data.Args[2],
		req.Data.Args[4],
	}
	args, err := t.processMemParse(req.Pid, argPtrs)
	if err != nil {
		return nil, err
	}

	mount := &mountSyscallInfo{
		syscallCtx: syscallCtx{
			syscallNum: int32(req.Data.Syscall),
			reqId:      req.Id,
			pid:        req.Pid,
			cntr:       cntr,
			tracer:     t,
		},
		MountSyscallPayload: &domain.MountSyscallPayload{
			Source: args[0],
			Target: args[1],
			FsType: args[2],
			Data:   args[3],
			Flags:  req.Data.Args[3],
		},
	}

	// Convert to absolute path if dealing with a relative path request.
	if !filepath.IsAbs(mount.Target) {
		cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", req.Pid))
		if err != nil {
			return nil, err
		}
		mount.Target = filepath.Join(cwd, mount.Target)
	}

	logrus.Debugf(mount.string())

	// As per man's capabilities(7), cap_sys_admin capability is required for
	// mount operations. Otherwise, return here and let kernel handle the mount
	// instruction.
	c, err := capability.NewPid2(int(req.Pid))
	if err != nil {
		return nil, err
	}
	if err = c.Load(); err != nil {
		return nil, err
	}
	if !(c.Get(capability.EFFECTIVE, capability.CAP_SYS_ADMIN)) {
		return t.createErrorResponse(req.Id, syscall.EPERM), nil
	}

	// Resolve mount target and verify that process has the proper rights to
	// access each of the components of the path.
	err = pathres.PathAccess(int(req.Pid), mount.Target, 0)
	if err != nil {
		return t.createErrorResponse(req.Id, err), nil
	}

	// Process mount syscall.
	return mount.process()
}

func (t *syscallTracer) processUmount(
	req *sysRequest,
	fd int32,
	cntr domain.ContainerIface) (*sysResponse, error) {

	logrus.Debugf("Received umount syscall from pid %d", req.Pid)

	argPtrs := []uint64{req.Data.Args[0]}
	args, err := t.processMemParse(req.Pid, argPtrs)
	if err != nil {
		return nil, err
	}

	umount := &umountSyscallInfo{
		syscallCtx: syscallCtx{
			syscallNum: int32(req.Data.Syscall),
			reqId:      req.Id,
			pid:        req.Pid,
			cntr:       cntr,
			tracer:     t,
		},
		UmountSyscallPayload: &domain.UmountSyscallPayload{
			Target: args[0],
			Flags:  req.Data.Args[1],
		},
	}

	// Convert to absolute path if dealing with a relative path request.
	if !filepath.IsAbs(umount.Target) {
		cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", req.Pid))
		if err != nil {
			return nil, err
		}
		umount.Target = filepath.Join(cwd, umount.Target)
	}

	logrus.Debugf(umount.string())

	// As per man's capabilities(7), cap_sys_admin capability is required for
	// umount operations. Otherwise, return here and let kernel handle the mount
	// instruction.
	c, err := capability.NewPid2(int(req.Pid))
	if err != nil {
		return nil, err
	}
	if err = c.Load(); err != nil {
		return nil, err
	}
	if !(c.Get(capability.EFFECTIVE, capability.CAP_SYS_ADMIN)) {
		return t.createErrorResponse(req.Id, syscall.EPERM), nil
	}

	// Resolve mount target and verify that process has the proper rights to
	// access each of the components of the path.
	err = pathres.PathAccess(int(req.Pid), umount.Target, 0)
	if err != nil {
		return t.createErrorResponse(req.Id, err), nil
	}

	// Process umount syscall.
	return umount.process()
}

func (t *syscallTracer) processReboot(
	req *sysRequest,
	fd int32,
	cntrID domain.ContainerIface) (*sysResponse, error) {

	logrus.Errorf("Received reboot syscall")

	return t.createSuccessResponse(req.Id), nil
}

func (t *syscallTracer) processSwapon(
	req *sysRequest,
	fd int32,
	cntr domain.ContainerIface) (*sysResponse, error) {

	logrus.Errorf("Received swapon syscall")

	return t.createSuccessResponse(req.Id), nil
}

func (t *syscallTracer) processSwapoff(
	req *sysRequest,
	fd int32,
	cntr domain.ContainerIface) (*sysResponse, error) {

	logrus.Errorf("Received swapoff syscall")

	return t.createSuccessResponse(req.Id), nil
}

// processMemParser iterates through the tracee process' /proc/pid/mem file to
// identify the indirect arguments utilized by the syscall in transit. The
// assumption here is that the process instantiating the syscall is 'stopped'
// at the time that this routine is executed. That is, tracee runs within a
// a single execution context (single-thread), and thereby, its memory can be
// safely referenced.
func (t *syscallTracer) processMemParse(pid uint32, argPtrs []uint64) ([]string, error) {

	name := fmt.Sprintf("/proc/%d/mem", pid)
	f, err := os.Open(name)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %s", name, err)
	}
	defer f.Close()

	result := make([]string, len(argPtrs))

	reader := bufio.NewReader(f)
	var line string

	// Iterate through the memory locations passed by caller.
	for i, address := range argPtrs {
		if address == 0 {
			result[i] = ""
		} else {
			reader.Reset(f)
			_, err := f.Seek(int64(address), 0)
			if err != nil {
				return nil, fmt.Errorf("seek of %s failed: %s", name, err)
			}
			line, err = reader.ReadString('\x00')
			if err != nil {
				return nil, fmt.Errorf("read of %s at offset %d failed: %s", name, address, err)
			}
			result[i] = strings.TrimSuffix(line, "\x00")
		}
	}

	return result, nil
}

func (t *syscallTracer) createSuccessResponse(id uint64) *sysResponse {

	resp := &sysResponse{
		Id:    id,
		Error: 0,
		Val:   0,
		Flags: 0,
	}

	return resp
}

func (t *syscallTracer) createContinueResponse(id uint64) *sysResponse {

	resp := &sysResponse{
		Id:    id,
		Error: 0,
		Val:   0,
		Flags: libseccomp.NotifRespFlagContinue,
	}

	return resp
}

func (t *syscallTracer) createErrorResponse(id uint64, err error) *sysResponse {

	resp := &sysResponse{
		Id:    id,
		Error: int32(err.(syscall.Errno)),
		Val:   0,
		Flags: 0,
	}

	return resp
}
