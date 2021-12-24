//
// Copyright 2019-2021 Nestybox, Inc.
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

package seccomp

import (
	"C"
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/nestybox/sysbox-fs/domain"
	unixIpc "github.com/nestybox/sysbox-ipc/unix"
	"github.com/nestybox/sysbox-libs/formatter"
	libseccomp "github.com/nestybox/sysbox-libs/libseccomp-golang"
	"github.com/nestybox/sysbox-libs/pidmonitor"
	"golang.org/x/sys/unix"

	"github.com/sirupsen/logrus"
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
	"chown",
	"fchown",
	"fchownat",
	"setxattr",
	"lsetxattr",
	"fsetxattr",
	"getxattr",
	"lgetxattr",
	"fgetxattr",
	"removexattr",
	"lremovexattr",
	"fremovexattr",
	"listxattr",
	"llistxattr",
	"flistxattr",
}

// Seccomp's syscall-monitoring/trapping service struct. External packages
// will solely rely on this struct for their syscall-monitoring demands.
type SyscallMonitorService struct {
	nss                    domain.NSenterServiceIface        // for nsenter functionality requirements
	css                    domain.ContainerStateServiceIface // for container-state interactions
	prs                    domain.ProcessServiceIface        // for process class interactions
	mts                    domain.MountServiceIface          // for mount-services purposes
	allowImmutableRemounts bool                              // allow immutable mounts to be remounted
	allowImmutableUnmounts bool                              // allow immutable mounts to be unmounted
	closeSeccompOnContExit bool                              // close seccomp fds on container exit, not on process exit
	tracer                 *syscallTracer                    // pointer to actual syscall-tracer instance
}

func NewSyscallMonitorService() *SyscallMonitorService {
	return &SyscallMonitorService{}
}

func (scs *SyscallMonitorService) Setup(
	nss domain.NSenterServiceIface,
	css domain.ContainerStateServiceIface,
	prs domain.ProcessServiceIface,
	mts domain.MountServiceIface,
	allowImmutableRemounts bool,
	allowImmutableUnmounts bool,
	seccompFdReleasePolicy string) {

	scs.nss = nss
	scs.css = css
	scs.prs = prs
	scs.mts = mts
	scs.allowImmutableRemounts = allowImmutableRemounts
	scs.allowImmutableUnmounts = allowImmutableUnmounts

	if seccompFdReleasePolicy == "cont-exit" {
		scs.closeSeccompOnContExit = true
	}

	// Allocate a new syscall-tracer.
	scs.tracer = newSyscallTracer(scs)

	// Initialize and launch the syscall-tracer.
	if err := scs.tracer.start(); err != nil {
		logrus.Fatalf("syscallMonitorService initialization error (%v). Exiting ...",
			err)
	}
}

// SeccompSession holds state associated to every seccomp tracee session.
type seccompSession struct {
	pid uint32 // pid of the tracee process
	fd  int32  // tracee's seccomp-fd to allow kernel interaction
}

// Seccomp's syscall-monitor/tracer.
type syscallTracer struct {
	srv                *unixIpc.Server                   // unix server listening to seccomp-notifs
	pollsrv            *unixIpc.PollServer               // unix pollserver for non-blocking i/o on seccomp-fd
	syscalls           map[libseccomp.ScmpSyscall]string // hashmap of supported syscalls, indexed by seccomp syscall id
	seccompSessionMap  map[uint32]int32                  // Tracks seccomp fd associated with a given pid
	seccompSessionCMap map[string][]seccompSession       // Tracks all seccomp sessions associated with a given container
	pidToContMap       map[uint32]string                 // Maps pid -> container id
	seccompSessionMu   sync.RWMutex                      // Seccomp session table lock
	pm                 *pidmonitor.PidMon                // Pid monitor (so we get notified when processes traced by seccomp die)
	service            *SyscallMonitorService            // backpointer to syscall-monitor service
}

// syscallTracer constructor.
func newSyscallTracer(sms *SyscallMonitorService) *syscallTracer {

	tracer := &syscallTracer{
		service:           sms,
		syscalls:          make(map[libseccomp.ScmpSyscall]string),
		seccompSessionMap: make(map[uint32]int32),
	}

	if sms.closeSeccompOnContExit {
		tracer.seccompSessionCMap = make(map[string][]seccompSession)
		tracer.pidToContMap = make(map[uint32]string)
	}

	// Populate hashmap of supported syscalls to monitor.
	for _, syscall := range monitoredSyscalls {
		syscallId, err := libseccomp.GetSyscallFromName(syscall)
		if err != nil {
			logrus.Warnf("Seccomp-tracer initialization error: unknown syscall (%v).",
				syscall)
			return nil
		}
		tracer.syscalls[syscallId] = syscall
	}

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

	return nil
}

func track(msg string) (string, time.Time) {
	return msg, time.Now()
}

func duration(msg string, start time.Time) {
	logrus.Infof("++++ %v ival: %v\n", msg, time.Since(start))
}

// Tracer's connection-handler method. Executed within a dedicated goroutine (one
// per connection).
func (t *syscallTracer) connHandler(c *net.UnixConn) {

	// Obtain seccomp-notification's file-descriptor and associated context.
	pid, cntrID, fd, err := unixIpc.RecvSeccompInitMsg(c)
	if err != nil {
		return
	}

	logrus.Debugf("Created seccomp-tracee session for pid: %d %s", pid, cntrID)

	// Send Ack message back to sysbox-runc.
	if err = unixIpc.SendSeccompInitAckMsg(c); err != nil {
		return
	}

	for {
		fds := []unix.PollFd{{int32(fd), unix.POLLIN, 0}}
		_, err := unix.Poll(fds, -1)
		if err != nil {
			if err == syscall.EINTR {
				logrus.Debugf("EINTR error during Poll() execution (%v) on fd %d pid %d", err, fd, pid)
				continue
			}

			logrus.Debugf("Error during Poll() execution (%v) on fd %d pid %d", err, fd, pid)
			break
		}

		if fds[0].Revents&unix.POLLIN!=unix.POLLIN {
			logrus.Debugf("Revent (%v) received during Poll() execution on fd %d pid %d", fds[0].Revents, fd, pid)
			break
		}

		// Retrieves seccomp-notification message.
		req, err := libseccomp.NotifReceive(libseccomp.ScmpFd(fd))
		if err != nil {
			break
		}

		// Process the incoming syscall and obtain response for seccomp-tracee.
		go t.process(req, fd, cntrID)
	}

	// We are finally ready to close the seccomp-fd. We don't want to do
	// this any earlier as kernel could potentially re-assign the same fd to
	// new seccomp-bpf sessions without giving us a chance to complete the fd
	// unregistration process.
	if err := unix.Close(int(fd)); err != nil {
		logrus.Errorf("failed to close seccomp fd %v for pid %d: %v", fd, pid, err)
	}
	c.Close()

	logrus.Debugf("Removed seccomp-tracee session for pid %d: fd(s) = %v", pid, fd)
}

// // Tracer's connection-handler method. Executed within a dedicated goroutine (one
// // per connection).
// func (t *syscallTracer) connHandler(c *net.UnixConn) error {

// 	// Obtain seccomp-notification's file-descriptor and associated context.
// 	pid, cntrID, fd, err := unixIpc.RecvSeccompInitMsg(c)
// 	if err != nil {
// 		return err
// 	}

// 	var (
// 		start_msg string
// 		start_time time.Time
// 		steady_msg string
// 		steady_time time.Time
// 		just_started = true
// 		pid_str string
// 	)

// 	pid_str = strconv.Itoa(int(pid))
// 	start_msg, start_time = track(fmt.Sprintf("Ready-to-read delay after start: %s", pid_str))

// 	logrus.Debugf("seccompTracer connection on fd %d from pid %d cntrId %s",
// 		fd, pid, formatter.ContainerID{cntrID})

// 	seccompSession := seccompSession{uint32(pid), fd}
// 	if err := t.seccompSessionAdd(seccompSession, cntrID); err != nil {
// 		return err
// 	}

// 	// Send Ack message back to sysbox-runc.
// 	if err = unixIpc.SendSeccompInitAckMsg(c); err != nil {
// 		return err
// 	}

// 	for {
// 		if !just_started {
// 			steady_msg, steady_time = track(fmt.Sprintf("Ready-to-read delay after syscall: %s", pid_str))
// 		}

// 		// Wait for an incoming seccomp-notification msg to be available.
// 		// Return here to exit this goroutine in case of error as that implies
// 		// that the seccomp-fd is not valid anymore.
// 		if err := t.seccompSessionRead(seccompSession); err != nil {
// 			logrus.Debugf("Failed to wait for seccomp session: %v", err)
// 			return err
// 		}

// 		if just_started {
// 			duration(start_msg, start_time)
// 			just_started = false
// 		} else {
// 			duration(steady_msg, steady_time)
// 		}

// 		// Retrieves seccomp-notification message.
// 		req, err := libseccomp.NotifReceive(libseccomp.ScmpFd(fd))
// 		if err != nil {
// 			if err == syscall.EINTR {
// 				logrus.Warnf("Incomplete NotifReceive() execution (%v) on fd %d pid %d",
// 					err, fd, pid)
// 				continue
// 			}

// 			logrus.Warnf("Unexpected error during NotifReceive() execution (%v) on fd %d pid %d",
// 				err, fd, pid)
// 			continue
// 		}

// 		// Process the incoming syscall and obtain response for seccomp-tracee.
// 		resp := t.process(req, fd, cntrID)

// 		// Responds to a previously received seccomp-notification.
// 		err = libseccomp.NotifRespond(libseccomp.ScmpFd(fd), resp)
// 		if err != nil {
// 			if err == syscall.EINTR {
// 				logrus.Warnf("Incomplete NotifRespond() execution (%v) on fd %d pid %d",
// 					err, fd, pid)
// 				continue
// 			}

// 			logrus.Warnf("Unexpected error during NotifRespond() execution (%v) on fd %d pid %d",
// 				err, fd, pid)
// 			continue
// 		}
// 	}

// 	return nil
// }

func (t *syscallTracer) process(
	req *sysRequest,
	fd int32,
	cntrID string) {

	// Process the incoming syscall and obtain response for seccomp-tracee.
	//resp := t.processSyscall(req, fd, cntrID)
	resp, err := t.processSyscall(req, fd, cntrID)
	if err != nil {
		logrus.Warnf("Syscall processing error: (%v) on fd %d pid %d",
			err, fd, req.Pid)
		return
	}

	// Responds to a previously received seccomp-notification.
	_ = libseccomp.NotifRespond(libseccomp.ScmpFd(fd), resp)
}

// Syscall processing entrypoint. Returns the response to be delivered to the
// process (seccomp-tracee) generating the syscall.
func (t *syscallTracer) processSyscall(
	req *sysRequest,
	fd int32,
	cntrID string) (*sysResponse, error) {

	var (
		resp *sysResponse
		err  error
	)

	// Obtain container associated to the received containerId value.
	cntr := t.service.css.ContainerLookupById(cntrID)
	if cntr == nil {
		logrus.Warnf("Received seccompNotifMsg generated by unknown container: %s",
			formatter.ContainerID{cntrID})
		return t.createErrorResponse(req.Id, syscall.Errno(syscall.EPERM)), nil
	}

	syscallId := req.Data.Syscall
	syscallName := t.syscalls[syscallId]

	switch syscallName {
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

	case "chown":
		resp, err = t.processChown(req, fd, cntr)

	case "fchown":
		resp, err = t.processFchown(req, fd, cntr)

	case "fchownat":
		resp, err = t.processFchownat(req, fd, cntr)

	case "setxattr", "lsetxattr":
		resp, err = t.processSetxattr(req, fd, cntr, syscallName)

	case "fsetxattr":
		resp, err = t.processFsetxattr(req, fd, cntr)

	case "getxattr", "lgetxattr":
		resp, err = t.processGetxattr(req, fd, cntr, syscallName)

	case "fgetxattr":
		resp, err = t.processFgetxattr(req, fd, cntr)

	case "removexattr", "lremovexattr":
		resp, err = t.processRemovexattr(req, fd, cntr, syscallName)

	case "fremovexattr":
		resp, err = t.processFremovexattr(req, fd, cntr)

	case "listxattr", "llistxattr":
		resp, err = t.processListxattr(req, fd, cntr, syscallName)

	case "flistxattr":
		resp, err = t.processFlistxattr(req, fd, cntr)

	default:
		logrus.Warnf("Unsupported syscall notification received (%v) on fd %d pid %d cntr %s",
			syscallId, fd, req.Pid, formatter.ContainerID{cntrID})
		return t.createErrorResponse(req.Id, syscall.EINVAL), nil
	}

	// If an 'infrastructure' error is encountered during syscall processing,
	// then return a common error back to tracee process. By 'infrastructure'
	// errors we are referring to problems beyond the end-user realm: EPERM
	// error during Open() doesn't qualify, whereas 'nsenter' operational
	// errors or inexistent "/proc/pid/mem" does.
	if err != nil {
		logrus.Warnf("Error during syscall %v processing on fd %d pid %d cntr %s (%v)",
			syscallName, fd, req.Pid, formatter.ContainerID{cntrID}, err)
		return t.createErrorResponse(req.Id, syscall.EINVAL), nil
	}

	// TOCTOU check.
	if err := libseccomp.NotifIdValid(libseccomp.ScmpFd(fd), req.Id); err != nil {
		logrus.Infof("TOCTOU check failed on fd %d pid %d cntr %s: req.Id is no longer valid (%s)",
			fd, req.Pid, formatter.ContainerID{cntrID}, err)
		return t.createErrorResponse(req.Id, err), fmt.Errorf("TOCTOU error")
	}

	return resp, nil
}

func (t *syscallTracer) processMount(
	req *sysRequest,
	fd int32,
	cntr domain.ContainerIface) (*sysResponse, error) {

	logrus.Debugf("Received mount syscall from pid %d", req.Pid)

	sourceBuf := make([]byte, unix.PathMax)
	targetBuf := make([]byte, unix.PathMax)
	fstypeBuf := make([]byte, unix.PathMax)
	dataBuf := make([]byte, unix.PathMax)

	// Extract the "path", "name", "fstype" and "data" attributes (null-delimited
	// strings).

	if err := t.ReadRetVal(
		req.Pid,
		[][]byte{sourceBuf},
		[]uint64{req.Data.Args[0]},
		unix.PathMax); err != nil {
		return t.createErrorResponse(req.Id, syscall.EPERM), nil
	}

	if err := t.ReadRetVal(
		req.Pid,
		[][]byte{targetBuf},
		[]uint64{req.Data.Args[1]},
		unix.PathMax); err != nil {
		return t.createErrorResponse(req.Id, syscall.EPERM), nil
	}

	if err := t.ReadRetVal(
		req.Pid,
		[][]byte{fstypeBuf},
		[]uint64{req.Data.Args[2]},
		unix.PathMax); err != nil {
		return t.createErrorResponse(req.Id, syscall.EPERM), nil
	}

	if err := t.ReadRetVal(
		req.Pid,
		[][]byte{dataBuf},
		[]uint64{req.Data.Args[4]},
		unix.PathMax); err != nil {
		return t.createErrorResponse(req.Id, syscall.EPERM), nil
	}

	source := C.GoString((*C.char)(unsafe.Pointer(&sourceBuf[0])))
	target := C.GoString((*C.char)(unsafe.Pointer(&targetBuf[0])))
	fstype := C.GoString((*C.char)(unsafe.Pointer(&fstypeBuf[0])))
	data := C.GoString((*C.char)(unsafe.Pointer(&dataBuf[0])))

	mount := &mountSyscallInfo{
		syscallCtx: syscallCtx{
			syscallNum: int32(req.Data.Syscall),
			reqId:      req.Id,
			pid:        req.Pid,
			cntr:       cntr,
			tracer:     t,
		},
		MountSyscallPayload: &domain.MountSyscallPayload{
			domain.NSenterMsgHeader{},
			domain.Mount{
				Source: source,
				Target: target,
				FsType: fstype,
				Data:   data,
				Flags:  req.Data.Args[3],
			},
		},
	}

	// cap_sys_admin capability is required for mount operations.
	process := t.service.prs.ProcessCreate(req.Pid, 0, 0)
	if !process.IsSysAdminCapabilitySet() {
		return t.createErrorResponse(req.Id, syscall.EPERM), nil
	}

	var err error

	mount.Source, err = process.ResolveProcSelf(mount.Source)
	if err != nil {
		return t.createErrorResponse(req.Id, syscall.EACCES), nil
	}

	mount.Target, err = process.ResolveProcSelf(mount.Target)
	if err != nil {
		return t.createErrorResponse(req.Id, syscall.EACCES), nil
	}

	// Verify the process has the proper rights to access the target
	err = process.PathAccess(mount.Target, 0, true)
	if err != nil {
		return t.createErrorResponse(req.Id, err), nil
	}

	// Collect process attributes required for mount execution.
	mount.uid = process.Uid()
	mount.gid = process.Gid()
	mount.cwd = process.Cwd()
	mount.root = process.Root()
	mount.processInfo = process

	logrus.Debug(mount)

	// To simplify mount processing logic, convert to absolute path if dealing
	// with a relative path request.
	if !filepath.IsAbs(mount.Target) {
		mount.Target = filepath.Join(mount.cwd, mount.Target)
	}

	// Process mount syscall.
	return mount.process()
}

func (t *syscallTracer) processUmount(
	req *sysRequest,
	fd int32,
	cntr domain.ContainerIface) (*sysResponse, error) {

	logrus.Debugf("Received umount syscall from pid %d", req.Pid)

	targetBuf := make([]byte, unix.PathMax)

	// Extract the "path" attribute.
	if err := t.ReadRetVal(
		req.Pid,
		[][]byte{targetBuf},
		[]uint64{req.Data.Args[0]},
		unix.PathMax); err != nil {
		return t.createErrorResponse(req.Id, syscall.EPERM), nil
	}

	target := C.GoString((*C.char)(unsafe.Pointer(&targetBuf[0])))

	umount := &umountSyscallInfo{
		syscallCtx: syscallCtx{
			syscallNum: int32(req.Data.Syscall),
			reqId:      req.Id,
			pid:        req.Pid,
			cntr:       cntr,
			tracer:     t,
		},
		UmountSyscallPayload: &domain.UmountSyscallPayload{
			domain.NSenterMsgHeader{},
			domain.Mount{
				Target: target,
				Flags:  req.Data.Args[1],
			},
		},
	}

	// As per man's capabilities(7), cap_sys_admin capability is required for
	// umount operations. Otherwise, return here and let kernel handle the mount
	// instruction.
	process := t.service.prs.ProcessCreate(req.Pid, 0, 0)
	if !(process.IsSysAdminCapabilitySet()) {
		return t.createErrorResponse(req.Id, syscall.EPERM), nil
	}

	var err error

	umount.Target, err = process.ResolveProcSelf(umount.Target)
	if err != nil {
		return t.createErrorResponse(req.Id, syscall.EACCES), nil
	}

	// Verify the process has the proper rights to access the target
	err = process.PathAccess(umount.Target, 0, true)
	if err != nil {
		return t.createErrorResponse(req.Id, err), nil
	}

	// Collect process attributes required for umount execution.
	umount.uid = process.Uid()
	umount.gid = process.Gid()
	umount.cwd = process.Cwd()
	umount.root = process.Root()
	umount.processInfo = process

	logrus.Debug(umount)

	// To simplify umount processing logic, convert to absolute path if dealing
	// with a relative path request.
	if !filepath.IsAbs(umount.Target) {
		umount.Target = filepath.Join(umount.cwd, umount.Target)
	}

	// Process umount syscall.
	return umount.process()
}

func (t *syscallTracer) processChown(
	req *sysRequest,
	fd int32,
	cntr domain.ContainerIface) (*sysResponse, error) {

	pathBuf := make([]byte, unix.PathMax)

	// Extract the "path" attribute.
	if err := t.ReadRetVal(
		req.Pid,
		[][]byte{pathBuf},
		[]uint64{req.Data.Args[0]},
		unix.PathMax); err != nil {
		return t.createErrorResponse(req.Id, syscall.EPERM), nil
	}

	path := C.GoString((*C.char)(unsafe.Pointer(&pathBuf[0])))

	uid := int64(req.Data.Args[1])
	gid := int64(req.Data.Args[2])

	chown := &chownSyscallInfo{
		syscallCtx: syscallCtx{
			syscallNum: int32(req.Data.Syscall),
			reqId:      req.Id,
			pid:        req.Pid,
			cntr:       cntr,
			tracer:     t,
		},
		path:     path,
		ownerUid: uid,
		ownerGid: gid,
	}

	return chown.processChown()
}

func (t *syscallTracer) processFchown(
	req *sysRequest,
	fd int32,
	cntr domain.ContainerIface) (*sysResponse, error) {

	// We trap fchown() for the same reason we trap chown() (see processChown()).

	pathFd := int32(req.Data.Args[0])
	uid := int64(req.Data.Args[1])
	gid := int64(req.Data.Args[2])

	chown := &chownSyscallInfo{
		syscallCtx: syscallCtx{
			syscallNum: int32(req.Data.Syscall),
			reqId:      req.Id,
			pid:        req.Pid,
			cntr:       cntr,
			tracer:     t,
		},
		pathFd:   pathFd,
		ownerUid: uid,
		ownerGid: gid,
	}

	return chown.processFchown()
}

func (t *syscallTracer) processFchownat(
	req *sysRequest,
	fd int32,
	cntr domain.ContainerIface) (*sysResponse, error) {

	// We trap fchownat() for the same reason we trap chown() (see processChown()).

	pathBuf := make([]byte, unix.PathMax)

	// Extract the "path" attribute.
	if err := t.ReadRetVal(
		req.Pid,
		[][]byte{pathBuf},
		[]uint64{req.Data.Args[1]},
		unix.PathMax); err != nil {
		return t.createErrorResponse(req.Id, syscall.EPERM), nil
	}

	path := C.GoString((*C.char)(unsafe.Pointer(&pathBuf[0])))

	// Get the other args
	dirFd := int32(req.Data.Args[0])
	uid := int64(req.Data.Args[2])
	gid := int64(req.Data.Args[3])
	flags := int(req.Data.Args[4])

	chown := &chownSyscallInfo{
		syscallCtx: syscallCtx{
			syscallNum: int32(req.Data.Syscall),
			reqId:      req.Id,
			pid:        req.Pid,
			cntr:       cntr,
			tracer:     t,
		},
		path:     path,
		ownerUid: uid,
		ownerGid: gid,
		dirFd:    dirFd,
		flags:    flags,
	}

	return chown.processFchownat()
}

func (t *syscallTracer) processSetxattr(
	req *sysRequest,
	fd int32,
	cntr domain.ContainerIface,
	syscallName string) (*sysResponse, error) {

	pathBuf := make([]byte, unix.PathMax)
	nameBuf := make([]byte, unix.PathMax)
	// Value size is defined by the args[3] parameter -- see setxattr(2).
	valBuf := make([]byte, req.Data.Args[3])

	// Extract the "path" and "name" attributes (null-delimited strings).

	if err := t.ReadRetVal(
		req.Pid,
		[][]byte{pathBuf},
		[]uint64{req.Data.Args[0]},
		unix.PathMax); err != nil {
		return t.createErrorResponse(req.Id, syscall.EPERM), nil
	}

	if err := t.ReadRetVal(
		req.Pid,
		[][]byte{nameBuf},
		[]uint64{req.Data.Args[1]},
		unix.PathMax); err != nil {
		return t.createErrorResponse(req.Id, syscall.EPERM), nil
	}

	// Exract the "value" attribute (delimited by the "size" argument).
	if err := t.ReadRetVal(
		req.Pid,
		[][]byte{valBuf},
		[]uint64{req.Data.Args[2]},
		int(req.Data.Args[3])); err != nil {
		return t.createErrorResponse(req.Id, syscall.EINVAL), nil
	}

	path := C.GoString((*C.char)(unsafe.Pointer(&pathBuf[0])))
	name := C.GoString((*C.char)(unsafe.Pointer(&nameBuf[0])))
	val := valBuf
	flags := int(req.Data.Args[4])

	si := &setxattrSyscallInfo{
		syscallCtx: syscallCtx{
			syscallNum:  int32(req.Data.Syscall),
			syscallName: syscallName,
			reqId:       req.Id,
			pid:         req.Pid,
			cntr:        cntr,
			tracer:      t,
		},
		path:  path,
		name:  name,
		val:   val,
		flags: flags,
	}

	return si.processSetxattr()
}

func (t *syscallTracer) processFsetxattr(
	req *sysRequest,
	fd int32,
	cntr domain.ContainerIface) (*sysResponse, error) {

	pathFd := int32(req.Data.Args[0])

	nameBuf := make([]byte, unix.PathMax)
	valBuf := make([]byte, req.Data.Args[3])

	// Extract the "name" attribute (null-delimited string).
	if err := t.ReadRetVal(
		req.Pid,
		[][]byte{nameBuf},
		[]uint64{req.Data.Args[1]},
		unix.PathMax); err != nil {
		return t.createErrorResponse(req.Id, syscall.EPERM), nil
	}

	name := C.GoString((*C.char)(unsafe.Pointer(&nameBuf[0])))

	// Extract the "value" attribute (delimited by the "size" argument).
	if err := t.ReadRetVal(
		req.Pid,
		[][]byte{valBuf},
		[]uint64{req.Data.Args[2]},
		int(req.Data.Args[3])); err != nil {
		return t.createErrorResponse(req.Id, syscall.EINVAL), nil
	}

	val := valBuf
	flags := int(req.Data.Args[4])

	si := &setxattrSyscallInfo{
		syscallCtx: syscallCtx{
			syscallNum: int32(req.Data.Syscall),
			reqId:      req.Id,
			pid:        req.Pid,
			cntr:       cntr,
			tracer:     t,
		},
		pathFd: pathFd,
		name:   name,
		val:    val,
		flags:  flags,
	}

	return si.processSetxattr()
}

func (t *syscallTracer) processGetxattr(
	req *sysRequest,
	fd int32,
	cntr domain.ContainerIface,
	syscallName string) (*sysResponse, error) {

	pathBuf := make([]byte, unix.PathMax)
	nameBuf := make([]byte, unix.NAME_MAX)

	// Extract the "path" and "name" attributes (null-delimited strings).
	if err := t.ReadRetVal(
		req.Pid,
		[][]byte{pathBuf, nameBuf},
		[]uint64{req.Data.Args[0], req.Data.Args[1]},
		unix.PathMax,
		unix.NAME_MAX); err != nil {
		return t.createErrorResponse(req.Id, syscall.EPERM), nil
	}

	path := C.GoString((*C.char)(unsafe.Pointer(&pathBuf[0])))
	name := C.GoString((*C.char)(unsafe.Pointer(&nameBuf[0])))

	// "addr" is the mem address where the syscall's result is stored; it's an
	// address in the virtual memory of the process that performed the syscall.
	// We will write the result there.
	addr := uint64(req.Data.Args[2])

	// "size" is the number of bytes in the buffer pointed to by "addr"; we must
	// never write more than this amount of bytes into that buffer. If set to 0
	// then getxattr will return the size of the extended attribute (and
	// not write into the buffer pointed to by "addr").
	size := uint64(req.Data.Args[3])

	si := &getxattrSyscallInfo{
		syscallCtx: syscallCtx{
			syscallNum:  int32(req.Data.Syscall),
			syscallName: syscallName,
			reqId:       req.Id,
			pid:         req.Pid,
			cntr:        cntr,
			tracer:      t,
		},
		path: path,
		name: name,
		addr: addr,
		size: size,
	}

	return si.processGetxattr()
}

func (t *syscallTracer) processFgetxattr(
	req *sysRequest,
	fd int32,
	cntr domain.ContainerIface) (*sysResponse, error) {

	pathFd := int32(req.Data.Args[0])

	nameBuf := make([]byte, unix.NAME_MAX)

	// Extract tne "name" attribute.
	if err := t.ReadRetVal(
		req.Pid,
		[][]byte{nameBuf},
		[]uint64{req.Data.Args[1]},
		unix.NAME_MAX); err != nil {
		return t.createErrorResponse(req.Id, syscall.EPERM), nil
	}

	name := C.GoString((*C.char)(unsafe.Pointer(&nameBuf[0])))

	// "addr" is the mem address where the syscall's result is stored; it's an
	// address in the virtual memory of the process that performed the syscall.
	// We will write the result there.
	addr := uint64(req.Data.Args[2])

	// "size" is the number of bytes in the buffer pointed to by "addr"; we must
	// never write more than this amount of bytes into that buffer. If set to 0
	// then getxattr will return the size of the extended attribute (and
	// not write into the buffer pointed to by "addr").
	size := uint64(req.Data.Args[3])

	si := &getxattrSyscallInfo{
		syscallCtx: syscallCtx{
			syscallNum: int32(req.Data.Syscall),
			reqId:      req.Id,
			pid:        req.Pid,
			cntr:       cntr,
			tracer:     t,
		},
		pathFd: pathFd,
		name:   name,
		addr:   addr,
		size:   size,
	}

	return si.processGetxattr()
}

func (t *syscallTracer) processRemovexattr(
	req *sysRequest,
	fd int32,
	cntr domain.ContainerIface,
	syscallName string) (*sysResponse, error) {

	pathBuf := make([]byte, unix.PathMax)
	nameBuf := make([]byte, unix.PathMax)

	// Extract the "path" and "name" attributes (null-delimited strings).

	if err := t.ReadRetVal(
		req.Pid,
		[][]byte{pathBuf},
		[]uint64{req.Data.Args[0]},
		unix.PathMax); err != nil {
		return t.createErrorResponse(req.Id, syscall.EPERM), nil
	}

	if err := t.ReadRetVal(
		req.Pid,
		[][]byte{nameBuf},
		[]uint64{req.Data.Args[1]},
		unix.PathMax); err != nil {
		return t.createErrorResponse(req.Id, syscall.EPERM), nil
	}

	path := C.GoString((*C.char)(unsafe.Pointer(&pathBuf[0])))
	name := C.GoString((*C.char)(unsafe.Pointer(&nameBuf[0])))

	si := &removexattrSyscallInfo{
		syscallCtx: syscallCtx{
			syscallNum:  int32(req.Data.Syscall),
			syscallName: syscallName,
			reqId:       req.Id,
			pid:         req.Pid,
			cntr:        cntr,
			tracer:      t,
		},
		path: path,
		name: name,
	}

	return si.processRemovexattr()
}

func (t *syscallTracer) processFremovexattr(
	req *sysRequest,
	fd int32,
	cntr domain.ContainerIface) (*sysResponse, error) {

	pathFd := int32(req.Data.Args[0])

	nameBuf := make([]byte, unix.PathMax)

	// Extract the "name" attribute (null-delimited string).
	if err := t.ReadRetVal(
		req.Pid,
		[][]byte{nameBuf},
		[]uint64{req.Data.Args[1]},
		unix.PathMax); err != nil {
		return t.createErrorResponse(req.Id, syscall.EPERM), nil
	}

	name := C.GoString((*C.char)(unsafe.Pointer(&nameBuf[0])))

	si := &removexattrSyscallInfo{
		syscallCtx: syscallCtx{
			syscallNum: int32(req.Data.Syscall),
			reqId:      req.Id,
			pid:        req.Pid,
			cntr:       cntr,
			tracer:     t,
		},
		pathFd: pathFd,
		name:   name,
	}

	return si.processRemovexattr()
}

func (t *syscallTracer) processListxattr(
	req *sysRequest,
	fd int32,
	cntr domain.ContainerIface,
	syscallName string) (*sysResponse, error) {

	pathBuf := make([]byte, unix.PathMax)

	// Extract the "path" attribute.
	if err := t.ReadRetVal(
		req.Pid,
		[][]byte{pathBuf},
		[]uint64{req.Data.Args[0]},
		unix.PathMax); err != nil {
		return t.createErrorResponse(req.Id, syscall.EPERM), nil
	}

	path := C.GoString((*C.char)(unsafe.Pointer(&pathBuf[0])))

	// "addr" is the mem address where the syscall's result is stored; it's an
	// address in the virtual memory of the process that performed the syscall.
	// We will write the result there.
	addr := uint64(req.Data.Args[1])

	// "size" is the number of bytes in the buffer pointed to by "addr"; we must
	// never write more than this amount of bytes into that buffer. If set to 0
	// then listxattr will return the size of the extended attribute (and
	// not write into the buffer pointed to by "addr").
	size := uint64(req.Data.Args[2])

	si := &listxattrSyscallInfo{
		syscallCtx: syscallCtx{
			syscallNum:  int32(req.Data.Syscall),
			syscallName: syscallName,
			reqId:       req.Id,
			pid:         req.Pid,
			cntr:        cntr,
			tracer:      t,
		},
		path: path,
		addr: addr,
		size: size,
	}

	return si.processListxattr()
}

func (t *syscallTracer) processFlistxattr(
	req *sysRequest,
	fd int32,
	cntr domain.ContainerIface) (*sysResponse, error) {

	pathFd := int32(req.Data.Args[0])

	// "addr" is the mem address where the syscall's result is stored; it's an
	// address in the virtual memory of the process that performed the syscall.
	// We will write the result there.
	addr := uint64(req.Data.Args[1])

	// "size" is the number of bytes in the buffer pointed to by "addr"; we must
	// never write more than this amount of bytes into that buffer. If set to 0
	// then listxattr will return the size of the extended attribute (and
	// not write into the buffer pointed to by "addr").
	size := uint64(req.Data.Args[2])

	si := &listxattrSyscallInfo{
		syscallCtx: syscallCtx{
			syscallNum: int32(req.Data.Syscall),
			reqId:      req.Id,
			pid:        req.Pid,
			cntr:       cntr,
			tracer:     t,
		},
		pathFd: pathFd,
		addr:   addr,
		size:   size,
	}

	return si.processListxattr()
}

func (t *syscallTracer) processReboot(
	req *sysRequest,
	fd int32,
	cntrID domain.ContainerIface) (*sysResponse, error) {

	logrus.Warnf("Received reboot syscall")

	return t.createSuccessResponse(req.Id), nil
}

func (t *syscallTracer) processSwapon(
	req *sysRequest,
	fd int32,
	cntr domain.ContainerIface) (*sysResponse, error) {

	logrus.Warnf("Received swapon syscall")

	return t.createSuccessResponse(req.Id), nil
}

func (t *syscallTracer) processSwapoff(
	req *sysRequest,
	fd int32,
	cntr domain.ContainerIface) (*sysResponse, error) {

	logrus.Warnf("Received swapoff syscall")

	return t.createSuccessResponse(req.Id), nil
}

func (t *syscallTracer) ReadRetVal(
	pid uint32,
	local [][]byte,
	remote []uint64,
	sizes ...int) error {

	var (
		localElements int = len(local)
		remoteElements int = len(remote)
		localIovec []unix.Iovec = make([]unix.Iovec, localElements)
		remoteIovec []unix.RemoteIovec = make([]unix.RemoteIovec, remoteElements)
		expectedCopySize int
		atLeastOne bool
	)

	for i := 0; i < localElements; i++ {
		localIovec[i].Base = &local[i][0]
		localIovec[i].Len = uint64(sizes[i])
		expectedCopySize += sizes[i]
	}

	if expectedCopySize == 0 {
		return nil
	}

	for i := 0; i < remoteElements; i++ {
		if uintptr(remote[i]) == 0 {
			continue
		}
		remoteIovec[i].Base = uintptr(remote[i])
		remoteIovec[i].Len = sizes[i]
		atLeastOne = true
	}

	if !atLeastOne {
		return nil
	}

	// Write to the traced process' memory
	n, err := unix.ProcessVMReadv(int(pid), localIovec, remoteIovec, 0)

	if err != nil {
		return fmt.Errorf("failed to read from mem of pid %d: %s", pid, err)
	} else if n > expectedCopySize {
		return fmt.Errorf("read more bytes (%d) from mem of pid %d than expected (%d)",
			n, pid, expectedCopySize)
	}

	return nil
}

func (t *syscallTracer) WriteRetVal(pid uint32, addr uint64, data []byte, size int) error {

	if size == 0 {
		return nil
	}

	data = data[:size]

	localIov := []unix.Iovec{
		{
			Base: &data[0],
			Len:  uint64(size),
		},
	}

	remoteIov := []unix.RemoteIovec{
		{
			Base: uintptr(addr),
			Len:  size,
		},
	}

	// Write to the traced process' memory
	n, err := unix.ProcessVMWritev(int(pid), localIov, remoteIov, 0)

	if err != nil {
		return fmt.Errorf("failed to write to mem of pid %d: %s", pid, err)
	} else if n != size {
		return fmt.Errorf("failed to write %d bytes to mem of pid %d: wrote %d bytes only", size, pid, n)
	}

	return nil
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

func (t *syscallTracer) createSuccessResponseWithRetValue(id, val uint64) *sysResponse {

	resp := &sysResponse{
		Id:    id,
		Error: 0,
		Val:   val,
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

	// Override the passed error if this one doesn't match the supported type.
	rcvdError, ok := err.(syscall.Errno)
	if !ok {
		rcvdError = syscall.EINVAL
	}

	resp := &sysResponse{
		Id:    id,
		Error: int32(rcvdError),
		Val:   0,
		Flags: 0,
	}

	return resp
}
