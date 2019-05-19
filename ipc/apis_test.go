package ipc_test

import (
	"io/ioutil"
	"log"
	"reflect"
	"testing"
	"time"

	"github.com/nestybox/sysvisor/sysvisor-fs/domain"
	"github.com/nestybox/sysvisor/sysvisor-fs/ipc"
	"github.com/nestybox/sysvisor/sysvisor-fs/state"
	"github.com/nestybox/sysvisor/sysvisor-fs/sysio"
	"github.com/nestybox/sysvisor/sysvisor-ipc/sysvisorFsGrpc"
	"github.com/spf13/afero"
)

func TestMain(m *testing.M) {

	// Disable log generation during UT.
	log.SetOutput(ioutil.Discard)

	m.Run()
}

func TestNewIpcService(t *testing.T) {
	type args struct {
		css domain.ContainerStateService
		ios domain.IOService
	}
	tests := []struct {
		name string
		args args
		want domain.IpcService
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ipc.NewIpcService(tt.args.css, tt.args.ios); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewIpcService() = %v, want %v", got, tt.want)
			}
		})
	}
}

/*
func Test_ipcService_Init(t *testing.T) {
	tests := []struct {
		name string
		s    *ipc.ipcService
	}{
		// TODO: Add test cases.

	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.s.Init()
		})
	}
}
*/

func TestContainerRegister(t *testing.T) {

	//
	// Test-cases common attributes.
	//
	var css = state.NewContainerStateService()
	var ios = sysio.NewIOService(sysio.IOFileService)

	var ipcs = ipc.NewIpcService(css, ios)

	// ContainerData objects received from external (ipc/grpc) module.
	cdata1 := &sysvisorFsGrpc.ContainerData{
		Id:      "cntr-1",
		InitPid: 1001,
	}

	cdata2 := &sysvisorFsGrpc.ContainerData{
		Id:      "cntr-2",
		InitPid: 1002,
	}

	//
	// Test-case definitions.
	//
	type args struct {
		ctx  interface{}
		data *sysvisorFsGrpc.ContainerData
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		prepare func()
	}{
		{
			//
			// Test-case 1: Proper registration request. No errors expected.
			//
			name:    "1",
			args:    args{ipcs, cdata1},
			wantErr: false,
			prepare: func() {

				// Create proc entry in mem-based FS.
				afero.WriteFile(sysio.AppFs, "/proc/1001/ns/pid", []byte("123456"), 0644)
			},
		},
		{
			//
			// Test-case 2: Missing pid-ns-inode for the pid associated to the
			//              incoming request. IOW, no pid-ns is found for this
			//              container. Error expected.
			//
			name:    "2",
			args:    args{ipcs, cdata2},
			wantErr: true,
			prepare: func() {

				// Create proc entry in mem-based FS.
				afero.WriteFile(sysio.AppFs, "/proc/1001/ns/pid", []byte("123456"), 0644)
			},
		},
		{
			//
			// Test-case 3: Add previously-inserted container.Error expected.
			//
			name:    "3",
			args:    args{ipcs, cdata1},
			wantErr: true,
			prepare: func() {

				// Create proc entry in mem-based FS.
				afero.WriteFile(sysio.AppFs, "/proc/1001/ns/pid", []byte("123456"), 0644)
			},
		},
	}

	//
	// Testcase executions.
	//
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Initialize memory-based mock FS.
			sysio.AppFs = afero.NewMemMapFs()

			// Prepare the mocks.
			if tt.prepare != nil {
				tt.prepare()
			}

			err := ipc.ContainerRegister(tt.args.ctx, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("ContainerRegister() error = %v, wantErr %v", err, tt.wantErr)
			}

			// Ensure that container has been added to state-DB.
			if err == nil {
				if cntr := css.ContainerLookupById(tt.args.data.Id); cntr == nil {
					t.Errorf("ContainerRegister() error: unexpected container absence")
				}
			}
		})
	}
}

func TestContainerUnregister(t *testing.T) {

	//
	// Test-cases common attributes.
	//
	var css = state.NewContainerStateService()
	var ios = sysio.NewIOService(sysio.IOFileService)

	var ipcs = ipc.NewIpcService(css, ios)

	// ContainerData objects being added to state-DB prior to test execution.
	cdata1 := &sysvisorFsGrpc.ContainerData{
		Id:      "cntr-1",
		InitPid: 1001,
	}
	cdata2 := &sysvisorFsGrpc.ContainerData{
		Id:      "cntr-2",
		InitPid: 1002,
	}
	ipc.ContainerRegister(ipcs, cdata1)

	//
	// Test-case definitions.
	//
	type args struct {
		ctx  interface{}
		data *sysvisorFsGrpc.ContainerData
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		prepare func()
	}{
		{
			//
			// Test-case 1: Proper unregistration request. No errors expected.
			//
			name:    "1",
			args:    args{ipcs, cdata1},
			wantErr: false,
			prepare: func() {

				// Create proc entry in mem-based FS.
				afero.WriteFile(sysio.AppFs, "/proc/1001/ns/pid", []byte("123456"), 0644)
			},
		},
		{
			//
			// Test-case 2: Missing pid-ns-inode for the pid associated to the
			//              incoming request. IOW, no pid-ns is found for this
			//              container. Error expected.
			//
			name:    "2",
			args:    args{ipcs, cdata2},
			wantErr: true,
			prepare: func() {

				// Create proc entry in mem-based FS.
				afero.WriteFile(sysio.AppFs, "/proc/1001/ns/pid", []byte("123456"), 0644)
			},
		},
		{
			//
			// Test-case 3: Unregister a previously-eliminated container.
			// Error expected.
			//
			name:    "3",
			args:    args{ipcs, cdata1},
			wantErr: true,
			prepare: func() {

				// Create proc entry in mem-based FS.
				afero.WriteFile(sysio.AppFs, "/proc/1001/ns/pid", []byte("123456"), 0644)
			},
		},
	}

	//
	// Testcase executions.
	//
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Initialize memory-based mock FS.
			sysio.AppFs = afero.NewMemMapFs()

			// Prepare the mocks.
			if tt.prepare != nil {
				tt.prepare()
			}

			if err := ipc.ContainerUnregister(tt.args.ctx, tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("ContainerUnregister() error = %v, wantErr %v", err, tt.wantErr)
			}

			// Ensure that container has been eliminated from state-DB.
			if cntr := css.ContainerLookupById(tt.args.data.Id); cntr != nil {
				t.Errorf("ContainerUnregister() error: unexpected container found")
			}
		})
	}
}

func TestContainerUpdate(t *testing.T) {

	//
	// Test-cases common attributes.
	//
	var css = state.NewContainerStateService()
	var ios = sysio.NewIOService(sysio.IOFileService)

	var ipcs = ipc.NewIpcService(css, ios)

	// ContainerData object being added to state-DB prior to test execution.
	cdata1 := &sysvisorFsGrpc.ContainerData{
		Id:      "cntr-1",
		InitPid: 1001,
	}
	ipc.ContainerRegister(ipcs, cdata1)

	// ContainerData objects to be utilized to generate updates.
	cdata1Update := &sysvisorFsGrpc.ContainerData{
		Id:      "cntr-1",
		InitPid: 1001,
		Ctime:   time.Date(2019, 05, 11, 00, 00, 00, 651387237, time.UTC),
	}
	cdata2Update := &sysvisorFsGrpc.ContainerData{
		Id:      "cntr-2",
		InitPid: 1002,
	}

	//
	// Test-case definitions.
	//
	type args struct {
		ctx  interface{}
		data *sysvisorFsGrpc.ContainerData
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		prepare func()
	}{
		{
			//
			// Test-case 1: Proper update request. No errors expected.
			//
			name:    "1",
			args:    args{ipcs, cdata1Update},
			wantErr: false,
			prepare: func() {

				// Create proc entry in mem-based FS.
				afero.WriteFile(sysio.AppFs, "/proc/1001/ns/pid", []byte("123456"), 0644)
			},
		},
		{
			//
			// Test-case 2: Missing pid-ns-inode for the pid associated to the
			//              incoming request. IOW, no pid-ns is found for this
			//              container. Error expected.
			//
			name:    "2",
			args:    args{ipcs, cdata2Update},
			wantErr: true,
			prepare: func() {

				// Create proc entry in mem-based FS.
				afero.WriteFile(sysio.AppFs, "/proc/1001/ns/pid", []byte("123456"), 0644)
			},
		},
		{
			//
			// Test-case 3: Update previously-inserted container.
			// Error expected.
			//
			name:    "3",
			args:    args{ipcs, cdata1Update},
			wantErr: false,
			prepare: func() {

				// Create proc entry in mem-based FS.
				afero.WriteFile(sysio.AppFs, "/proc/1001/ns/pid", []byte("123456"), 0644)
			},
		},
	}

	//
	// Testcase executions.
	//
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Initialize memory-based mock FS.
			sysio.AppFs = afero.NewMemMapFs()

			// Prepare the mocks.
			if tt.prepare != nil {
				tt.prepare()
			}

			err := ipc.ContainerUpdate(tt.args.ctx, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("ContainerUpdate() error = %v, wantErr %v", err, tt.wantErr)
			}

			// Ensure that container has been updated in state-DB.
			if err == nil {
				if cntr := css.ContainerLookupById(tt.args.data.Id); cntr == nil {
					if tt.args.data.Id != cntr.ID() ||
						uint32(tt.args.data.InitPid) != cntr.InitPid() ||
						tt.args.data.Ctime != cntr.Ctime() {
						t.Errorf("ContainerUpdate() error: unexpected container attribute")
					}
				}
			}
		})
	}
}