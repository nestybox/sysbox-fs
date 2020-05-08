package seccomp

import (
	"errors"
	"fmt"
	"reflect"
	"syscall"
	"testing"

	libseccomp "github.com/nestybox/libseccomp-golang"
	unixIpc "github.com/nestybox/sysbox-ipc/unix"
)

// func TestNewSyscallMonitorService(t *testing.T) {
// 	type args struct {
// 		nss domain.NSenterService
// 		css domain.ContainerStateService
// 		hns domain.HandlerService
// 		prs domain.ProcessService
// 	}
// 	tests := []struct {
// 		name string
// 		args args
// 		want *SyscallMonitorService
// 	}{
// 		// TODO: Add test cases.
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			if got := NewSyscallMonitorService(tt.args.nss, tt.args.css, tt.args.hns, tt.args.prs); !reflect.DeepEqual(got, tt.want) {
// 				t.Errorf("NewSyscallMonitorService() = %v, want %v", got, tt.want)
// 			}
// 		})
// 	}
// }

// func Test_newSyscallTracer(t *testing.T) {
// 	type args struct {
// 		sms *SyscallMonitorService
// 	}
// 	tests := []struct {
// 		name string
// 		args args
// 		want *syscallTracer
// 	}{
// 		// TODO: Add test cases.
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			if got := newSyscallTracer(tt.args.sms); !reflect.DeepEqual(got, tt.want) {
// 				t.Errorf("newSyscallTracer() = %v, want %v", got, tt.want)
// 			}
// 		})
// 	}
// }

// func Test_syscallTracer_start(t *testing.T) {
// 	type fields struct {
// 		sms              *SyscallMonitorService
// 		srv              *unixIpc.Server
// 		pollsrv          *unixIpc.PollServer
// 		syscalls         map[libseccomp.ScmpSyscall]string
// 		mountHelper      *mountHelper
// 		seccompSessionCh chan seccompSession
// 	}
// 	tests := []struct {
// 		name    string
// 		fields  fields
// 		wantErr bool
// 	}{
// 		// TODO: Add test cases.
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			t := &syscallTracer{
// 				sms:              tt.fields.sms,
// 				srv:              tt.fields.srv,
// 				pollsrv:          tt.fields.pollsrv,
// 				syscalls:         tt.fields.syscalls,
// 				mountHelper:      tt.fields.mountHelper,
// 				seccompSessionCh: tt.fields.seccompSessionCh,
// 			}
// 			if err := t.start(); (err != nil) != tt.wantErr {
// 				t.Errorf("syscallTracer.start() error = %v, wantErr %v", err, tt.wantErr)
// 			}
// 		})
// 	}
// }

// func Test_syscallTracer_sessionsMonitor(t *testing.T) {
// 	type fields struct {
// 		sms              *SyscallMonitorService
// 		srv              *unixIpc.Server
// 		pollsrv          *unixIpc.PollServer
// 		syscalls         map[libseccomp.ScmpSyscall]string
// 		mountHelper      *mountHelper
// 		seccompSessionCh chan seccompSession
// 	}
// 	tests := []struct {
// 		name    string
// 		fields  fields
// 		wantErr bool
// 	}{
// 		// TODO: Add test cases.
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			t := &syscallTracer{
// 				sms:              tt.fields.sms,
// 				srv:              tt.fields.srv,
// 				pollsrv:          tt.fields.pollsrv,
// 				syscalls:         tt.fields.syscalls,
// 				mountHelper:      tt.fields.mountHelper,
// 				seccompSessionCh: tt.fields.seccompSessionCh,
// 			}
// 			if err := t.sessionsMonitor(); (err != nil) != tt.wantErr {
// 				t.Errorf("syscallTracer.sessionsMonitor() error = %v, wantErr %v", err, tt.wantErr)
// 			}
// 		})
// 	}
// }

// func Test_syscallTracer_connHandler(t *testing.T) {
// 	type fields struct {
// 		sms              *SyscallMonitorService
// 		srv              *unixIpc.Server
// 		pollsrv          *unixIpc.PollServer
// 		syscalls         map[libseccomp.ScmpSyscall]string
// 		mountHelper      *mountHelper
// 		seccompSessionCh chan seccompSession
// 	}
// 	type args struct {
// 		c *net.UnixConn
// 	}
// 	tests := []struct {
// 		name    string
// 		fields  fields
// 		args    args
// 		wantErr bool
// 	}{
// 		// TODO: Add test cases.
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			t := &syscallTracer{
// 				sms:              tt.fields.sms,
// 				srv:              tt.fields.srv,
// 				pollsrv:          tt.fields.pollsrv,
// 				syscalls:         tt.fields.syscalls,
// 				mountHelper:      tt.fields.mountHelper,
// 				seccompSessionCh: tt.fields.seccompSessionCh,
// 			}
// 			if err := t.connHandler(tt.args.c); (err != nil) != tt.wantErr {
// 				t.Errorf("syscallTracer.connHandler() error = %v, wantErr %v", err, tt.wantErr)
// 			}
// 		})
// 	}
// }

// func Test_syscallTracer_process(t *testing.T) {
// 	type fields struct {
// 		sms              *SyscallMonitorService
// 		srv              *unixIpc.Server
// 		pollsrv          *unixIpc.PollServer
// 		syscalls         map[libseccomp.ScmpSyscall]string
// 		mountHelper      *mountHelper
// 		seccompSessionCh chan seccompSession
// 	}
// 	type args struct {
// 		req    *sysRequest
// 		fd     int32
// 		cntrID string
// 	}
// 	tests := []struct {
// 		name   string
// 		fields fields
// 		args   args
// 		want   *sysResponse
// 	}{
// 		// TODO: Add test cases.
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			t := &syscallTracer{
// 				sms:              tt.fields.sms,
// 				srv:              tt.fields.srv,
// 				pollsrv:          tt.fields.pollsrv,
// 				syscalls:         tt.fields.syscalls,
// 				mountHelper:      tt.fields.mountHelper,
// 				seccompSessionCh: tt.fields.seccompSessionCh,
// 			}
// 			if got := t.process(tt.args.req, tt.args.fd, tt.args.cntrID); !reflect.DeepEqual(got, tt.want) {
// 				t.Errorf("syscallTracer.process() = %v, want %v", got, tt.want)
// 			}
// 		})
// 	}
// }

// func Test_syscallTracer_processMount(t *testing.T) {
// 	type fields struct {
// 		sms              *SyscallMonitorService
// 		srv              *unixIpc.Server
// 		pollsrv          *unixIpc.PollServer
// 		syscalls         map[libseccomp.ScmpSyscall]string
// 		mountHelper      *mountHelper
// 		seccompSessionCh chan seccompSession
// 	}
// 	type args struct {
// 		req  *sysRequest
// 		fd   int32
// 		cntr domain.ContainerIface
// 	}
// 	tests := []struct {
// 		name    string
// 		fields  fields
// 		args    args
// 		want    *sysResponse
// 		wantErr bool
// 	}{
// 		// TODO: Add test cases.
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			t := &syscallTracer{
// 				sms:              tt.fields.sms,
// 				srv:              tt.fields.srv,
// 				pollsrv:          tt.fields.pollsrv,
// 				syscalls:         tt.fields.syscalls,
// 				mountHelper:      tt.fields.mountHelper,
// 				seccompSessionCh: tt.fields.seccompSessionCh,
// 			}
// 			got, err := t.processMount(tt.args.req, tt.args.fd, tt.args.cntr)
// 			if (err != nil) != tt.wantErr {
// 				t.Errorf("syscallTracer.processMount() error = %v, wantErr %v", err, tt.wantErr)
// 				return
// 			}
// 			if !reflect.DeepEqual(got, tt.want) {
// 				t.Errorf("syscallTracer.processMount() = %v, want %v", got, tt.want)
// 			}
// 		})
// 	}
// }

// func Test_syscallTracer_processUmount(t *testing.T) {
// 	type fields struct {
// 		sms              *SyscallMonitorService
// 		srv              *unixIpc.Server
// 		pollsrv          *unixIpc.PollServer
// 		syscalls         map[libseccomp.ScmpSyscall]string
// 		mountHelper      *mountHelper
// 		seccompSessionCh chan seccompSession
// 	}
// 	type args struct {
// 		req  *sysRequest
// 		fd   int32
// 		cntr domain.ContainerIface
// 	}
// 	tests := []struct {
// 		name    string
// 		fields  fields
// 		args    args
// 		want    *sysResponse
// 		wantErr bool
// 	}{
// 		// TODO: Add test cases.
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			t := &syscallTracer{
// 				sms:              tt.fields.sms,
// 				srv:              tt.fields.srv,
// 				pollsrv:          tt.fields.pollsrv,
// 				syscalls:         tt.fields.syscalls,
// 				mountHelper:      tt.fields.mountHelper,
// 				seccompSessionCh: tt.fields.seccompSessionCh,
// 			}
// 			got, err := t.processUmount(tt.args.req, tt.args.fd, tt.args.cntr)
// 			if (err != nil) != tt.wantErr {
// 				t.Errorf("syscallTracer.processUmount() error = %v, wantErr %v", err, tt.wantErr)
// 				return
// 			}
// 			if !reflect.DeepEqual(got, tt.want) {
// 				t.Errorf("syscallTracer.processUmount() = %v, want %v", got, tt.want)
// 			}
// 		})
// 	}
// }

// func Test_syscallTracer_processReboot(t *testing.T) {
// 	type fields struct {
// 		sms              *SyscallMonitorService
// 		srv              *unixIpc.Server
// 		pollsrv          *unixIpc.PollServer
// 		syscalls         map[libseccomp.ScmpSyscall]string
// 		mountHelper      *mountHelper
// 		seccompSessionCh chan seccompSession
// 	}
// 	type args struct {
// 		req    *sysRequest
// 		fd     int32
// 		cntrID domain.ContainerIface
// 	}
// 	tests := []struct {
// 		name    string
// 		fields  fields
// 		args    args
// 		want    *sysResponse
// 		wantErr bool
// 	}{
// 		// TODO: Add test cases.
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			t := &syscallTracer{
// 				sms:              tt.fields.sms,
// 				srv:              tt.fields.srv,
// 				pollsrv:          tt.fields.pollsrv,
// 				syscalls:         tt.fields.syscalls,
// 				mountHelper:      tt.fields.mountHelper,
// 				seccompSessionCh: tt.fields.seccompSessionCh,
// 			}
// 			got, err := t.processReboot(tt.args.req, tt.args.fd, tt.args.cntrID)
// 			if (err != nil) != tt.wantErr {
// 				t.Errorf("syscallTracer.processReboot() error = %v, wantErr %v", err, tt.wantErr)
// 				return
// 			}
// 			if !reflect.DeepEqual(got, tt.want) {
// 				t.Errorf("syscallTracer.processReboot() = %v, want %v", got, tt.want)
// 			}
// 		})
// 	}
// }

// func Test_syscallTracer_processSwapon(t *testing.T) {
// 	type fields struct {
// 		sms              *SyscallMonitorService
// 		srv              *unixIpc.Server
// 		pollsrv          *unixIpc.PollServer
// 		syscalls         map[libseccomp.ScmpSyscall]string
// 		mountHelper      *mountHelper
// 		seccompSessionCh chan seccompSession
// 	}
// 	type args struct {
// 		req  *sysRequest
// 		fd   int32
// 		cntr domain.ContainerIface
// 	}
// 	tests := []struct {
// 		name    string
// 		fields  fields
// 		args    args
// 		want    *sysResponse
// 		wantErr bool
// 	}{
// 		// TODO: Add test cases.
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			t := &syscallTracer{
// 				sms:              tt.fields.sms,
// 				srv:              tt.fields.srv,
// 				pollsrv:          tt.fields.pollsrv,
// 				syscalls:         tt.fields.syscalls,
// 				mountHelper:      tt.fields.mountHelper,
// 				seccompSessionCh: tt.fields.seccompSessionCh,
// 			}
// 			got, err := t.processSwapon(tt.args.req, tt.args.fd, tt.args.cntr)
// 			if (err != nil) != tt.wantErr {
// 				t.Errorf("syscallTracer.processSwapon() error = %v, wantErr %v", err, tt.wantErr)
// 				return
// 			}
// 			if !reflect.DeepEqual(got, tt.want) {
// 				t.Errorf("syscallTracer.processSwapon() = %v, want %v", got, tt.want)
// 			}
// 		})
// 	}
// }

// func Test_syscallTracer_processSwapoff(t *testing.T) {
// 	type fields struct {
// 		sms              *SyscallMonitorService
// 		srv              *unixIpc.Server
// 		pollsrv          *unixIpc.PollServer
// 		syscalls         map[libseccomp.ScmpSyscall]string
// 		mountHelper      *mountHelper
// 		seccompSessionCh chan seccompSession
// 	}
// 	type args struct {
// 		req  *sysRequest
// 		fd   int32
// 		cntr domain.ContainerIface
// 	}
// 	tests := []struct {
// 		name    string
// 		fields  fields
// 		args    args
// 		want    *sysResponse
// 		wantErr bool
// 	}{
// 		// TODO: Add test cases.
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			t := &syscallTracer{
// 				sms:              tt.fields.sms,
// 				srv:              tt.fields.srv,
// 				pollsrv:          tt.fields.pollsrv,
// 				syscalls:         tt.fields.syscalls,
// 				mountHelper:      tt.fields.mountHelper,
// 				seccompSessionCh: tt.fields.seccompSessionCh,
// 			}
// 			got, err := t.processSwapoff(tt.args.req, tt.args.fd, tt.args.cntr)
// 			if (err != nil) != tt.wantErr {
// 				t.Errorf("syscallTracer.processSwapoff() error = %v, wantErr %v", err, tt.wantErr)
// 				return
// 			}
// 			if !reflect.DeepEqual(got, tt.want) {
// 				t.Errorf("syscallTracer.processSwapoff() = %v, want %v", got, tt.want)
// 			}
// 		})
// 	}
// }

// func Test_syscallTracer_processMemParse(t *testing.T) {
// 	type fields struct {
// 		sms              *SyscallMonitorService
// 		srv              *unixIpc.Server
// 		pollsrv          *unixIpc.PollServer
// 		syscalls         map[libseccomp.ScmpSyscall]string
// 		mountHelper      *mountHelper
// 		seccompSessionCh chan seccompSession
// 	}
// 	type args struct {
// 		pid     uint32
// 		argPtrs []uint64
// 	}
// 	tests := []struct {
// 		name    string
// 		fields  fields
// 		args    args
// 		want    []string
// 		wantErr bool
// 	}{
// 		// TODO: Add test cases.
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			t := &syscallTracer{
// 				sms:              tt.fields.sms,
// 				srv:              tt.fields.srv,
// 				pollsrv:          tt.fields.pollsrv,
// 				syscalls:         tt.fields.syscalls,
// 				mountHelper:      tt.fields.mountHelper,
// 				seccompSessionCh: tt.fields.seccompSessionCh,
// 			}
// 			got, err := t.processMemParse(tt.args.pid, tt.args.argPtrs)
// 			if (err != nil) != tt.wantErr {
// 				t.Errorf("syscallTracer.processMemParse() error = %v, wantErr %v", err, tt.wantErr)
// 				return
// 			}
// 			if !reflect.DeepEqual(got, tt.want) {
// 				t.Errorf("syscallTracer.processMemParse() = %v, want %v", got, tt.want)
// 			}
// 		})
// 	}
// }

// func Test_syscallTracer_createSuccessResponse(t *testing.T) {
// 	type fields struct {
// 		sms              *SyscallMonitorService
// 		srv              *unixIpc.Server
// 		pollsrv          *unixIpc.PollServer
// 		syscalls         map[libseccomp.ScmpSyscall]string
// 		mountHelper      *mountHelper
// 		seccompSessionCh chan seccompSession
// 	}
// 	type args struct {
// 		id uint64
// 	}
// 	tests := []struct {
// 		name   string
// 		fields fields
// 		args   args
// 		want   *sysResponse
// 	}{
// 		// TODO: Add test cases.
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			t := &syscallTracer{
// 				sms:              tt.fields.sms,
// 				srv:              tt.fields.srv,
// 				pollsrv:          tt.fields.pollsrv,
// 				syscalls:         tt.fields.syscalls,
// 				mountHelper:      tt.fields.mountHelper,
// 				seccompSessionCh: tt.fields.seccompSessionCh,
// 			}
// 			if got := t.createSuccessResponse(tt.args.id); !reflect.DeepEqual(got, tt.want) {
// 				t.Errorf("syscallTracer.createSuccessResponse() = %v, want %v", got, tt.want)
// 			}
// 		})
// 	}
// }

// func Test_syscallTracer_createContinueResponse(t *testing.T) {
// 	type fields struct {
// 		sms              *SyscallMonitorService
// 		srv              *unixIpc.Server
// 		pollsrv          *unixIpc.PollServer
// 		syscalls         map[libseccomp.ScmpSyscall]string
// 		mountHelper      *mountHelper
// 		seccompSessionCh chan seccompSession
// 	}
// 	type args struct {
// 		id uint64
// 	}
// 	tests := []struct {
// 		name   string
// 		fields fields
// 		args   args
// 		want   *sysResponse
// 	}{
// 		// TODO: Add test cases.
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			t := &syscallTracer{
// 				sms:              tt.fields.sms,
// 				srv:              tt.fields.srv,
// 				pollsrv:          tt.fields.pollsrv,
// 				syscalls:         tt.fields.syscalls,
// 				mountHelper:      tt.fields.mountHelper,
// 				seccompSessionCh: tt.fields.seccompSessionCh,
// 			}
// 			if got := t.createContinueResponse(tt.args.id); !reflect.DeepEqual(got, tt.want) {
// 				t.Errorf("syscallTracer.createContinueResponse() = %v, want %v", got, tt.want)
// 			}
// 		})
// 	}
// }

func Test_syscallTracer_createErrorResponse(t *testing.T) {
	type fields struct {
		sms              *SyscallMonitorService
		srv              *unixIpc.Server
		pollsrv          *unixIpc.PollServer
		syscalls         map[libseccomp.ScmpSyscall]string
		mountHelper      *mountHelper
		seccompSessionCh chan seccompSession
	}

	var f1 = &fields{
		sms:              nil,
		srv:              nil,
		pollsrv:          nil,
		syscalls:         nil,
		mountHelper:      nil,
		seccompSessionCh: nil,
	}

	// Expected results.

	var r1 = &sysResponse{
		Id:    0,
		Error: int32(syscall.EPERM),
		Val:   0,
		Flags: 0,
	}
	var r2 = &sysResponse{
		Id:    1,
		Error: int32(syscall.EINVAL),
		Val:   0,
		Flags: 0,
	}

	type args struct {
		id  uint64
		err error
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *sysResponse
	}{
		// A received syscall.Errno error must be honored (no modifications allowed).
		{"1", *f1, args{0, syscall.EPERM}, r1},

		// Verify that "errorString" errors are properly type-asserted.
		{"2", *f1, args{1, fmt.Errorf("testing errorString error type 1")}, r2},

		// Same as above but with another error constructor.
		{"3", *f1, args{1, errors.New("testing errorString error type 2")}, r2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracer := &syscallTracer{
				sms:              tt.fields.sms,
				srv:              tt.fields.srv,
				pollsrv:          tt.fields.pollsrv,
				syscalls:         tt.fields.syscalls,
				mountHelper:      tt.fields.mountHelper,
				seccompSessionCh: tt.fields.seccompSessionCh,
			}
			if got := tracer.createErrorResponse(tt.args.id, tt.args.err); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("syscallTracer.createErrorResponse() = %v, want %v", got, tt.want)
			}
		})
	}
}
