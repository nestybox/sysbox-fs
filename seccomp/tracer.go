package seccomp

import (
	"bufio"
	"net"
	"os"
	"fmt"
	"strings"
	"syscall"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	unixIpc "github.com/nestybox/sysbox-ipc/unix"
	"github.com/syndtr/gocapability/capability"
	libseccomp "github.com/seccomp/libseccomp-golang"
	"github.com/nestybox/sysbox-fs/domain"
)

const seccompTracerSockAddr = "/run/sysbox/sysfs-seccomp.sock"

// Default set of mount-flags utilized to mount /var/lib/sysboxfs into sysbox's
// system containers. This default set must be taken into account at the time
// procfs nodes are bind-mounted into L2 app-containers, as the flags to utilize
// for each node must match the ones utilized within L1 sys containers.
//
// TODO: Note that these flags are not chosen by sysbox-fs nor Bazil's FUSE
// library implementations, so they are subject to change in subsequent kernel
// upgrades. Therefore, our implementation should ideally extract these flags
// from each system (e.g. by parsing /proc/mounts) to avoid hard-coding their
// values as we are doing below.
const sysboxfsDefaultMountFlags =
	unix.MS_BIND | unix.MS_REC | unix.MS_NODEV | unix.MS_NOSUID | unix.MS_RELATIME

// Set of mount-flags to skip during mount syscall processing. Notice that with
// the exception of MS_BIND and MS_REMOUNT, all these flags are associated to
// operations that modify existing mount-points, which corresponds to actions
// that the kernel (and not sysboxfs) should execute.
const sysboxSkipMountFlags =
	unix.MS_SHARED | unix.MS_PRIVATE | unix.MS_SLAVE | unix.MS_UNBINDABLE | unix.MS_MOVE


// Slice of supported syscalls to monitor.
var monitoredSyscalls = []string{
	"mount",
	"reboot",
	"swapon",
	"swapoff",
}

// Syscall success-response template.
var syscallSuccessResponse = &libseccomp.ScmpNotifResp{
	Id:    0,
	Error: 0,
	Val:   0,
	Flags: 0,
}

// Syscall error-response template.
var syscallErrorResponse = &libseccomp.ScmpNotifResp{
	Id:    0,
	Error: int32(syscall.EPERM),
	Val:   0,
	Flags: 0,
}

// Syscall continue-response template.
var syscallContinueResponse = &libseccomp.ScmpNotifResp{
	Id:    0,
	Error: 0,
	Val:   0,
	Flags: libseccomp.NotifRespFlagContinue,
}


// Seccomp's syscall-monitoring/trapping service struct. External packages
// will solely rely on this struct for their syscall-monitoring demands.
type SyscallMonitorService struct {
	css    domain.ContainerStateService // for container-state interactions
	nss    domain.NSenterService        // for nsenter functionality requirements
	tracer *syscallTracer               // pointer to actual syscall-tracer instance
}

func NewSyscallMonitorService(
	css domain.ContainerStateService,
	nss domain.NSenterService) *SyscallMonitorService {

	svc := &SyscallMonitorService{
		css: css,
		nss: nss,
	}

	// Allocate a new syscall-tracer.
	svc.tracer = newSyscallTracer(svc)

	// Initialize and launch the syscall-tracer.
	if err := svc.tracer.start(); err != nil {
		return nil
	}

	return svc
}

// Seccomp's syscall-monitor/tracer.
type syscallTracer struct {
	sms      *SyscallMonitorService             // backpointer to syscall-monitor service
	srv      *unixIpc.Server                    // unix server listening to seccomp-notifs
	syscalls map[libseccomp.ScmpSyscall]string  // hashmap of supported syscalls indexed by id
}

func newSyscallTracer(sms *SyscallMonitorService) *syscallTracer {

	tracer := &syscallTracer{
		sms: sms,
		syscalls: make(map[libseccomp.ScmpSyscall]string),
	}

	// Populate hash-map of supported syscalls to monitor.
	for _, syscall := range monitoredSyscalls {
		syscallId, err := libseccomp.GetSyscallFromName(syscall)
		if err != nil {
			logrus.Errorf("Unknown syscall to monitor %v (%v).")
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

// Tracer's connection handler method. Executed within a dedicated goroutine (one
// per connection).
func (t *syscallTracer) connHandler(c *net.UnixConn) error {

	logrus.Infof("seccompTracer client connection %v", c.RemoteAddr())

	// Obtain seccomp-notification's file-descriptor and associated context (cntr).
	fd, cntrId, err := unixIpc.RecvSeccompNotifMsg(c)
	if err != nil {
		return err
	}

	// Send Ack message back to sysbox-runc.
	if err = unixIpc.SendSeccompNotifAckMsg(c); err != nil {
		return err
	}

	for {
		// Retrieves a seccomp-notification.
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
		resp, err := t.process(req, fd, cntrId)
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

func (t *syscallTracer) process(
	req *libseccomp.ScmpNotifReq,
	fd int32,
	cntrId string) (*libseccomp.ScmpNotifResp, error) {

	var (
		resp *libseccomp.ScmpNotifResp
		err error
	)

	// Obtain container associated to the received containerId value.
	cntr := t.sms.css.ContainerLookupById(cntrId)
	if cntr == nil {
		syscallErrorResponse.Id = req.Id
		logrus.Errorf("Received seccompNotifMsg generated by unknown container: %v",
			cntrId)
		return syscallErrorResponse, nil
	}

	syscallId := req.Data.Syscall
	syscall := t.syscalls[syscallId]

	switch syscall {

	case "mount":
		resp, err = t.processMount(req, fd, cntr)

	case "reboot":
		resp, err = t.processReboot(req, fd, cntr)

	case "swapon":
		resp, err = t.processSwapon(req, fd, cntr)

	case "swapoff":
		resp, err = t.processSwapoff(req, fd, cntr)

	default:
		logrus.Errorf("Unsupported syscall notification received (%v).", syscallId)
		return nil, fmt.Errorf("Unsupported syscall notification.")
	}

	if err != nil {
		logrus.Errorf("Error during syscall \"%v\" processing (%v).", syscall, err)
		return nil, err
	}

	// TOCTOU check.
	if err := libseccomp.NotifIdValid(libseccomp.ScmpFd(fd), req.Id); err != nil {
		syscallErrorResponse.Id = req.Id
		logrus.Errorf("TOCTOU check failed: req.Id is no longer valid (%s).", err)
		return syscallErrorResponse, err
	}

	return resp, nil
}

func (t *syscallTracer) processMount(
	req *libseccomp.ScmpNotifReq,
	fd int32,
	cntr domain.ContainerIface) (*libseccomp.ScmpNotifResp, error) {

	logrus.Debug("Received mount syscall.")

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
		syscallInfo: syscallInfo{
			syscallNum: int32(req.Data.Syscall),
			pid:        req.Pid,
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

	logrus.Debugf("source: %s, target: %s, type: %s, flags: %v\n",
		mount.Source, mount.Target, mount.FsType, mount.Flags)


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
		syscallContinueResponse.Id = req.Id
		return syscallContinueResponse, nil
	}

	// We are interested in processing a very reduced set of mount syscalls.
	// Return here if the received syscall doesn't match the following
	// criteria:
	//
	// * 'proc' fsType and associated '/proc' source OR ...
	// * '/proc/sys' source and '/proc/sys' target
	// * AND in both cases (above), mount-flags should be associated to new-mount
	// operations.
	if !(((mount.FsType == "proc" && mount.Source == "proc") ||
		(mount.Source == "/proc/sys" && mount.Target == "/proc/sys")) &&
		(mount.Flags &^ sysboxSkipMountFlags == mount.Flags)) {
		syscallContinueResponse.Id = req.Id
		return syscallContinueResponse, nil
	}

	// Mount "/proc" into the passed mount target, and bind-mount "/proc/sys"
	// into the corresponding target folder.
	if mount.Source == "proc" {
        if err := mount.processProcMount(); err != nil {
            syscallErrorResponse.Id = req.Id
            return syscallErrorResponse, nil
        }

	// Process incoming "/proc/sys" bind-mount instructions.
	} else if mount.Source == "/proc/sys" {
		logrus.Debugf("source 11: %s, target: %s, type: %s, flags: %v\n",
			mount.Source, mount.Target, mount.FsType, mount.Flags)

		// Disregard "/proc/sys" pure bind operations (no new flag settings) as
		// we are already taking care of this task as part of "/proc" new mount
		// requests.
		if mount.Flags &^ sysboxfsDefaultMountFlags == 0 {
			syscallSuccessResponse.Id = req.Id
			return syscallSuccessResponse, nil
		}

		logrus.Debugf("source 12: %s, target: %s, type: %s, flags: %v\n",
			mount.Source, mount.Target, mount.FsType, mount.Flags)

		if err := mount.processProcSysMount(); err != nil {
			syscallErrorResponse.Id = req.Id
			return syscallErrorResponse, nil
		}
    }

    syscallSuccessResponse.Id = req.Id
    return syscallSuccessResponse, nil
}

func (t *syscallTracer) processReboot(
	req *libseccomp.ScmpNotifReq,
	fd int32,
	cntrId domain.ContainerIface) (*libseccomp.ScmpNotifResp, error) {

	logrus.Errorf("Received reboot syscall")

	syscallSuccessResponse.Id = req.Id
	return syscallSuccessResponse, nil
}

func (t *syscallTracer) processSwapon(
	req *libseccomp.ScmpNotifReq,
	fd int32,
	cntr domain.ContainerIface) (*libseccomp.ScmpNotifResp, error) {

	logrus.Errorf("Received swapon syscall")

	syscallSuccessResponse.Id = req.Id
	return syscallSuccessResponse, nil
}

func (t *syscallTracer) processSwapoff(
	req *libseccomp.ScmpNotifReq,
	fd int32,
	cntr domain.ContainerIface) (*libseccomp.ScmpNotifResp, error) {

	logrus.Errorf("Received swapoff syscall")

	syscallSuccessResponse.Id = req.Id
	return syscallSuccessResponse, nil
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
