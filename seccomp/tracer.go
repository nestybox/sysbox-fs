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
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

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

	// The pid monitor tells us when processes traced by seccomp die; we use a
	// 500ms sampling rate, so that if a process dies we get notified within
	// 500ms at worst. If we make the delay shorter, we may get overwhelmed by
	// notifications (for scenarios where lots of system containers are exiting
	// at the same time). If we make the delay too long, we run the risk of the
	// kernel reusing a pid and thus we don't notice that the pid died and end up
	// with a stale seccomp fd.
	pm, err := pidmonitor.New(&pidmonitor.Cfg{500})
	if err != nil {
		logrus.Warnf("Could not initialize pid monitor: %s", err)
		return nil
	}
	tracer.pm = pm

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

	// Launch a pollServer where to register the fds associated to all the
	// seccomp-tracees.
	pollsrv, err := unixIpc.NewPollServer()
	if err != nil {
		logrus.Errorf("Unable to initialize seccomp-tracer pollserver")
		return err
	}
	t.pollsrv = pollsrv

	go t.seccompSessionsMonitor()

	return nil
}

func (t *syscallTracer) seccompSessionAdd(s seccompSession, cntrID string) error {

	t.seccompSessionMu.Lock()
	t.seccompSessionMap[s.pid] = s.fd

	if t.service.closeSeccompOnContExit {

		// Collect seccomp fds associated with container so we can
		// release them together when the container dies.

		t.pidToContMap[s.pid] = cntrID
		sessions, ok := t.seccompSessionCMap[cntrID]
		if ok {
			sessions = append(sessions, s)
			t.seccompSessionCMap[cntrID] = sessions
		} else {
			t.seccompSessionCMap[cntrID] = []seccompSession{s}
		}
	}

	t.seccompSessionMu.Unlock()

	err := t.pm.AddEvent([]pidmonitor.PidEvent{
		pidmonitor.PidEvent{
			Pid:   s.pid,
			Event: pidmonitor.Exit,
			Err:   nil,
		},
	})

	logrus.Debugf("Added session for seccomp-tracee: %v %v", s, cntrID)
	return err
}

func (t *syscallTracer) seccompSessionDelete(pid uint32) {
	var closeFds []int32

	t.seccompSessionMu.Lock()
	fd, ok := t.seccompSessionMap[pid]
	if !ok {
		t.seccompSessionMu.Unlock()
		logrus.Warnf("Unexpected error: seccomp fd not found for pid %d", pid)
		return
	}

	if t.service.closeSeccompOnContExit {
		cntrID, ok := t.pidToContMap[pid]

		if ok {
			var cntrInitPid uint32

			cntr := t.service.css.ContainerLookupById(cntrID)
			if cntr != nil {
				cntrInitPid = cntr.InitPid()
			}

			// if the container is no longer there, or the pid being deleted is the
			// container's init pid, we close all seccomp sessions for that container
			if cntr == nil || pid == cntrInitPid {
				sessions := t.seccompSessionCMap[cntrID]
				for _, s := range sessions {
					closeFds = append(closeFds, s.fd)
					delete(t.seccompSessionMap, s.pid)
				}
				delete(t.seccompSessionCMap, cntrID)
			}

			delete(t.pidToContMap, pid)
		} else {
			logrus.Warnf("Unexpected error: pid %d is not associated with a container", pid)
		}

	} else {
		closeFds = []int32{fd}
		delete(t.seccompSessionMap, pid)
	}

	t.seccompSessionMu.Unlock()

	if len(closeFds) > 0 {
		for _, fd := range closeFds {

			// Alert the tracer's pollServer to stop polling on this seccomp-fd. Note
			// that this occurs after we delete the pid from the seccomp session map,
			// meaning that no new read operation can be launched from the tracer for
			// the fd being eliminated.
			if err := t.pollsrv.StopWait(fd); err != nil {
				logrus.Errorf("failed StopWait execution of seccomp fd %d for pid %d: %v",
					fd, pid, err)
			}

			// We are finally ready to close the seccomp-fd. We don't want to do
			// this any earlier as kernel could potentially re-assign the same fd to
			// new seccomp-bpf sessions without giving us a chance to complete the fd
			// unregistration process.
			if err := syscall.Close(int(fd)); err != nil {
				logrus.Errorf("failed to close seccomp fd %v for pid %d: %v", fd, pid, err)
			}
		}

		logrus.Debugf("Removed session for seccomp-tracee for pid %d: fd(s) = %v", pid, closeFds)
	}
}

func (t *syscallTracer) seccompSessionRead(s seccompSession) error {

	t.seccompSessionMu.RLock()

	_, ok := t.seccompSessionMap[s.pid]
	if !ok {
		t.seccompSessionMu.RUnlock()
		return fmt.Errorf("Seccomp session not found for pid %d fd %d", s.pid, s.fd)
	}
	t.seccompSessionMu.RUnlock()

	if err := t.pollsrv.StartWaitRead(s.fd); err != nil {
		logrus.Debugf("Seccomp-fd i/o error returned (%v). Exiting seccomp-tracer processing on fd %d pid %d",
			err, s.fd, s.pid)
		return err
	}

	return nil
}

// Go routine that tracks of all sessions traced by a syscall tracer. From a
// functional standpoint, this routine acts as a garbage-collector, in the sense
// that it detects when traced sessions are no longer valid (i.e., the associated
// process has died) and removes them if so.
func (t *syscallTracer) seccompSessionsMonitor() error {

	for {
		pidList := <-t.pm.EventCh
		for _, pidEvent := range pidList {
			t.seccompSessionDelete(pidEvent.Pid)

			// This sleep prevents seccompSessionDelete() from hogging the
			// seccompSessionMu lock; this gives priority to function
			// seccompSessionAdd() to get the lock when needed.
			time.Sleep(10 * time.Microsecond)
		}
	}

	return nil
}

// Tracer's connection-handler method. Executed within a dedicated goroutine (one
// per connection).
func (t *syscallTracer) connHandler(c *net.UnixConn) error {

	// Obtain seccomp-notification's file-descriptor and associated context.
	pid, cntrID, fd, err := unixIpc.RecvSeccompInitMsg(c)
	if err != nil {
		return err
	}

	logrus.Debugf("seccompTracer connection on fd %d from pid %d cntrId %s",
		fd, pid, formatter.ContainerID{cntrID})

	seccompSession := seccompSession{uint32(pid), fd}
	if err := t.seccompSessionAdd(seccompSession, cntrID); err != nil {
		return err
	}

	// Send Ack message back to sysbox-runc.
	if err = unixIpc.SendSeccompInitAckMsg(c); err != nil {
		return err
	}

	for {
		// Wait for an incoming seccomp-notification msg to be available.
		// Return here to exit this goroutine in case of error as that implies
		// that the seccomp-fd is not valid anymore.
		if err := t.seccompSessionRead(seccompSession); err != nil {
			logrus.Debugf("Failed to wait for seccomp session: %v", err)
			return err
		}

		// Retrieves seccomp-notification message.
		req, err := libseccomp.NotifReceive(libseccomp.ScmpFd(fd))
		if err != nil {
			if err == syscall.EINTR {
				logrus.Warnf("Incomplete NotifReceive() execution (%v) on fd %d pid %d",
					err, fd, pid)
				continue
			}

			logrus.Warnf("Unexpected error during NotifReceive() execution (%v) on fd %d pid %d",
				err, fd, pid)
			continue
		}

		// Process the incoming syscall and obtain response for seccomp-tracee.
		resp := t.process(req, fd, cntrID)

		// Responds to a previously received seccomp-notification.
		err = libseccomp.NotifRespond(libseccomp.ScmpFd(fd), resp)
		if err != nil {
			if err == syscall.EINTR {
				logrus.Warnf("Incomplete NotifRespond() execution (%v) on fd %d pid %d",
					err, fd, pid)
				continue
			}

			logrus.Warnf("Unexpected error during NotifRespond() execution (%v) on fd %d pid %d",
				err, fd, pid)
			continue
		}
	}

	return nil
}

// Syscall processing entrypoint. Returns the response to be delivered to the
// process (seccomp-tracee) generating the syscall.
func (t *syscallTracer) process(
	req *sysRequest,
	fd int32,
	cntrID string) *sysResponse {

	var (
		resp *sysResponse
		err  error
	)

	// Obtain container associated to the received containerId value.
	cntr := t.service.css.ContainerLookupById(cntrID)
	if cntr == nil {
		logrus.Warnf("Received seccompNotifMsg generated by unknown container: %s",
			formatter.ContainerID{cntrID})
		return t.createErrorResponse(req.Id, syscall.Errno(syscall.EPERM))
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
		return t.createErrorResponse(req.Id, syscall.EINVAL)
	}

	// If an 'infrastructure' error is encountered during syscall processing,
	// then return a common error back to tracee process. By 'infrastructure'
	// errors we are referring to problems beyond the end-user realm: EPERM
	// error during Open() doesn't qualify, whereas 'nsenter' operational
	// errors or inexistent "/proc/pid/mem" does.
	if err != nil {
		logrus.Warnf("Error during syscall %v processing on fd %d pid %d cntr %s (%v)",
			syscallName, fd, req.Pid, formatter.ContainerID{cntrID}, err)
		return t.createErrorResponse(req.Id, syscall.EINVAL)
	}

	// TOCTOU check.
	if err := libseccomp.NotifIdValid(libseccomp.ScmpFd(fd), req.Id); err != nil {
		logrus.Infof("TOCTOU check failed on fd %d pid %d cntr %s: req.Id is no longer valid (%s)",
			fd, req.Pid, formatter.ContainerID{cntrID}, err)
		return t.createErrorResponse(req.Id, err)
	}

	return resp
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

	args, err := t.parseStringArgs(req.Pid, argPtrs)
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
			domain.NSenterMsgHeader{},
			domain.Mount{
				Source: args[0],
				Target: args[1],
				FsType: args[2],
				Data:   args[3],
				Flags:  req.Data.Args[3],
			},
		},
	}

	// cap_sys_admin capability is required for mount operations.
	process := t.service.prs.ProcessCreate(req.Pid, 0, 0)
	if !process.IsSysAdminCapabilitySet() {
		return t.createErrorResponse(req.Id, syscall.EPERM), nil
	}

	mount.Source, err = process.ResolveProcSelf(mount.Source)
	if err != nil {
		return t.createErrorResponse(req.Id, syscall.EACCES), nil
	}

	mount.Target, err = process.ResolveProcSelf(mount.Target)
	if err != nil {
		return t.createErrorResponse(req.Id, syscall.EACCES), nil
	}

	// Verify the process has the proper rights to access the target
	err = process.PathAccess(mount.Target, 0)
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

	argPtrs := []uint64{req.Data.Args[0]}
	args, err := t.parseStringArgs(req.Pid, argPtrs)
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
			domain.NSenterMsgHeader{},
			domain.Mount{
				Target: args[0],
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

	umount.Target, err = process.ResolveProcSelf(umount.Target)
	if err != nil {
		return t.createErrorResponse(req.Id, syscall.EACCES), nil
	}

	// Verify the process has the proper rights to access the target
	err = process.PathAccess(umount.Target, 0)
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

	argPtrs := []uint64{req.Data.Args[0]}
	args, err := t.parseStringArgs(req.Pid, argPtrs)
	if err != nil {
		return nil, err
	}

	if len(args) < 1 {
		return t.createErrorResponse(req.Id, syscall.EINVAL), nil
	}

	path := args[0]
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

	// Get the path argument
	argPtrs := []uint64{req.Data.Args[1]}
	args, err := t.parseStringArgs(req.Pid, argPtrs)
	if err != nil {
		return nil, err
	}

	if len(args) < 1 {
		return t.createErrorResponse(req.Id, syscall.EINVAL), nil
	}

	path := args[0]

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

	// Parse the *path and *name arguments (null-delimited strings)
	strArgPtrs := []uint64{
		req.Data.Args[0],
		req.Data.Args[1],
	}

	strArgs, err := t.parseStringArgs(req.Pid, strArgPtrs)
	if err != nil {
		return nil, err
	}

	// Parse the "*value" argument (delimited by the "size" argument)
	byteArgs, err := t.parseByteArgs(req.Pid, []uint64{req.Data.Args[2]}, []uint64{req.Data.Args[3]})
	if err != nil {
		return nil, err
	}

	if len(byteArgs) != 1 {
		return t.createErrorResponse(req.Id, syscall.EINVAL), nil
	}

	path := strArgs[0]
	name := strArgs[1]
	val := byteArgs[0]
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

	// Parse the *name argument (null-delimited string)
	strArgs, err := t.parseStringArgs(req.Pid, []uint64{req.Data.Args[1]})
	if err != nil {
		return nil, err
	}

	// Parse the "*value" argument (delimited by the "size" argument)
	byteArgs, err := t.parseByteArgs(req.Pid, []uint64{req.Data.Args[2]}, []uint64{req.Data.Args[3]})
	if err != nil {
		return nil, err
	}

	if len(byteArgs) != 1 {
		return t.createErrorResponse(req.Id, syscall.EINVAL), nil
	}

	name := strArgs[0]
	val := byteArgs[0]
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

	// Parse the *path and *name arguments (null-delimited strings)
	strArgPtrs := []uint64{
		req.Data.Args[0],
		req.Data.Args[1],
	}

	strArgs, err := t.parseStringArgs(req.Pid, strArgPtrs)
	if err != nil {
		return nil, err
	}

	path := strArgs[0]
	name := strArgs[1]

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

	// Parse the *name argument (null-delimited string)
	strArgs, err := t.parseStringArgs(req.Pid, []uint64{req.Data.Args[1]})
	if err != nil {
		return nil, err
	}

	name := strArgs[0]

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

	// Parse the *path and *name arguments (null-delimited strings)
	strArgPtrs := []uint64{
		req.Data.Args[0],
		req.Data.Args[1],
	}

	strArgs, err := t.parseStringArgs(req.Pid, strArgPtrs)
	if err != nil {
		return nil, err
	}

	path := strArgs[0]
	name := strArgs[1]

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

	// Parse the *name argument (null-delimited string)
	strArgs, err := t.parseStringArgs(req.Pid, []uint64{req.Data.Args[1]})
	if err != nil {
		return nil, err
	}

	name := strArgs[0]

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

	// Parse the *path argument (null-delimited string)
	strArgs, err := t.parseStringArgs(req.Pid, []uint64{req.Data.Args[0]})
	if err != nil {
		return nil, err
	}

	path := strArgs[0]

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

// parseStringArgs iterates through the tracee process' /proc/pid/mem file to
// identify string (i.e., null-terminated) arguments utilized by the traced
// syscall. The assumption here is that the process invoking the syscall is
// 'stopped' at the time that this routine is executed. That is, tracee runs
// within a a single execution context (single-thread), and thefore its memory
// can be safely referenced.
func (t *syscallTracer) parseStringArgs(pid uint32, argPtrs []uint64) ([]string, error) {

	// TODO: consider using unix.ProcessVMReadv() to perform this operation (instead of /proc/<pid>/mem).

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
	for i, addr := range argPtrs {
		if addr == 0 {
			result[i] = ""
		} else {
			reader.Reset(f)
			_, err := f.Seek(int64(addr), 0)
			if err != nil {
				return nil, fmt.Errorf("seek of %s failed: %s", name, err)
			}
			line, err = reader.ReadString('\x00')
			if err != nil {
				return nil, fmt.Errorf("read of %s at offset %d failed: %s", name, addr, err)
			}
			result[i] = strings.TrimSuffix(line, "\x00")
		}
	}

	return result, nil
}

// parseByteArgs iterates through the tracee process' /proc/pid/mem file to
// identify arbitrary byte data arguments utilized by the traced
// syscall. argPtrs contains the mem addresses (in the tracee's address space)
// where the data resides; argSize contains the size of the data associated
// with each argPtr.
func (t *syscallTracer) parseByteArgs(pid uint32, argPtrs []uint64, argSize []uint64) ([][]byte, error) {

	if len(argSize) != len(argPtrs) {
		return nil, fmt.Errorf("expected length of argSize and argPtrs to match; got %d %d", len(argSize), len(argPtrs))
	}

	// TODO: consider using unix.ProcessVMReadv() to perform this operation (instead of /proc/<pid>/mem).

	name := fmt.Sprintf("/proc/%d/mem", pid)
	f, err := os.Open(name)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %s", name, err)
	}
	defer f.Close()

	result := make([][]byte, len(argPtrs))
	reader := bufio.NewReader(f)

	for i, addr := range argPtrs {
		if addr == 0 {
			result[i] = []byte{}
		} else {
			size := argSize[i]

			reader.Reset(f)
			_, err := f.Seek(int64(addr), 0)
			if err != nil {
				return nil, fmt.Errorf("seek of %s failed: %s", name, err)
			}

			// read the number of bytes specified by "size" (exactly)
			byteData := make([]byte, size)
			_, err = io.ReadFull(reader, byteData)
			if err != nil {
				return nil, fmt.Errorf("read of %s at offset %d with size %d failed: %s", name, addr, size, err)
			}

			result[i] = byteData
		}
	}

	return result, nil
}

func (t *syscallTracer) WriteRetVal(pid uint32, addr uint64, data []byte) error {

	size := len(data)

	if size == 0 {
		return nil
	}

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
