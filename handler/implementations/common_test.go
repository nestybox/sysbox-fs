package implementations_test

import (
	"io/ioutil"
	"log"
	"os"
	"reflect"
	"syscall"
	"testing"
	"time"

	"github.com/nestybox/sysvisor/sysvisor-fs/domain"
	"github.com/nestybox/sysvisor/sysvisor-fs/handler"
	"github.com/nestybox/sysvisor/sysvisor-fs/handler/implementations"
	"github.com/nestybox/sysvisor/sysvisor-fs/mocks"
	"github.com/nestybox/sysvisor/sysvisor-fs/nsenter"
	"github.com/nestybox/sysvisor/sysvisor-fs/state"
	"github.com/nestybox/sysvisor/sysvisor-fs/sysio"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {

	// Disable log generation during UT.
	log.SetOutput(ioutil.Discard)

	m.Run()
}

func TestCommonHandler_Lookup(t *testing.T) {

	//
	// Test-cases common attributes.
	//
	var css = state.NewContainerStateService()
	var ios = sysio.NewIOService(sysio.IOFileService)
	var nss = &mocks.NSenterService{}

	var hds = handler.NewHandlerService(handler.DefaultHandlers, css, nss, ios)

	// Handler to test.
	var h = &implementations.CommonHandler{
		Name:    "common",
		Path:    "commonHandler",
		Service: hds,
	}

	// Resource to Lookup().
	var r = ios.NewIOnode("net", "/proc/sys/net", 0)

	// Create new container and add it to the containerDB.
	cntr := css.ContainerCreate("cntr-1", 1001, "syscntr1", 123456, time.Time{}, 0, 0, 0, 0)
	err := css.ContainerAdd(cntr)
	if err != nil {
		return
	}

	//
	// Test-case definitions.
	//
	type args struct {
		n   domain.IOnode
		pid uint32
	}
	tests := []struct {
		name    string
		h       *implementations.CommonHandler
		args    args
		want    os.FileInfo
		wantErr bool
		prepare func(m *mocks.NSenterService)
	}{
		{
			//
			// Test-case 1: Regular lookup operation. No errors expected.
			//
			name:    "1",
			h:       h,
			args:    args{r, 1001},
			want:    domain.FileInfo{Fname: "/proc/sys/net"},
			wantErr: false,
			prepare: func(m *mocks.NSenterService) {

				// Create proc entry in mem-based FS.
				afero.WriteFile(sysio.AppFs, "/proc/1001/ns/pid", []byte("123456"), 0644)

				expectedResponse := &nsenter.NSenterEvent{
					Resource:  "/proc/sys/net",
					Pid:       1001,
					Namespace: []domain.NStype{string(domain.NStypeNet)},
					ReqMsg: &domain.NSenterMessage{
						Type:    domain.LookupRequest,
						Payload: "/proc/sys/net",
					},
					ResMsg: &domain.NSenterMessage{
						Type: domain.LookupResponse,
						Payload: domain.FileInfo{
							Fname: "/proc/sys/net"},
					},
				}

				nss.On("NewEvent", "/proc/sys/net", uint32(1001),
					[]domain.NStype{string(domain.NStypeNet)},
					expectedResponse.ReqMsg,
					(*domain.NSenterMessage)(nil)).Return(expectedResponse)

				nss.On("LaunchEvent", expectedResponse).Return(nil)

				nss.On("ResponseEvent", expectedResponse).Return(expectedResponse.ResMsg)
			},
		},
		{
			//
			// Test-case 2: Missing pid-ns-inode for the pid associated to the
			//              incoming request. IOW, no pid-ns is found for this
			//              container. Error expected.
			//
			name:    "2",
			h:       h,
			args:    args{r, 1002},
			want:    domain.FileInfo{Fname: "/proc/sys/net"},
			wantErr: true,
			prepare: func(m *mocks.NSenterService) {

				// Create proc entry in mem-based FS.
				afero.WriteFile(sysio.AppFs, "/proc/1001/ns/pid", []byte("123456"), 0644)
			},
		},
		{
			//
			// Test-case 3: Missing a container matching the pid-ns-inode associated
			//              to the pid of the incoming request. Error expected.
			//
			name:    "3",
			h:       h,
			args:    args{r, 1001},
			want:    domain.FileInfo{Fname: "/proc/sys/net"},
			wantErr: true,
			prepare: func(m *mocks.NSenterService) {

				// Create proc entry in mem-based FS.
				afero.WriteFile(sysio.AppFs, "/proc/1001/ns/pid", []byte("11111"), 0644)
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
				tt.prepare(nss)
			}

			// Run function to test.
			got, err := tt.h.Lookup(tt.args.n, tt.args.pid)
			if (err != nil) != tt.wantErr {
				t.Errorf("CommonHandler.Lookup() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Ensure results match expectations.
			if tt.wantErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
				assert.Equal(t, tt.want, got)
			}

			// Ensure that mocks were properly invoked.
			nss.AssertExpectations(t)
		})
	}
}

func TestCommonHandler_Getattr(t *testing.T) {

	//
	// Test-cases common attributes.
	//
	var css = state.NewContainerStateService()
	var ios = sysio.NewIOService(sysio.IOFileService)
	var nss = &mocks.NSenterService{}

	var hds = handler.NewHandlerService(handler.DefaultHandlers, css, nss, ios)

	// Handler to test.
	var h = &implementations.CommonHandler{
		Name:    "common",
		Path:    "commonHandler",
		Service: hds,
	}

	// Resource to obtain Getattr() for.
	var r = ios.NewIOnode("net", "/proc/sys/net", 0)

	// Create new container and add it to the containerDB.
	cntr := css.ContainerCreate(
		"cntr-1",
		1001,
		"syscntr1",
		123456,
		time.Time{},
		231072,
		65535,
		231072,
		65535,
	)
	err := css.ContainerAdd(cntr)
	if err != nil {
		return
	}

	//
	// Test-case definitions.
	//
	type args struct {
		n   domain.IOnode
		pid uint32
	}
	tests := []struct {
		name    string
		h       *implementations.CommonHandler
		args    args
		want    *syscall.Stat_t
		wantErr bool
		prepare func()
	}{
		{
			//
			// Test-case 1: Regular Getattr operation. No errors expected.
			//
			name:    "1",
			h:       h,
			args:    args{r, 1001},
			want:    &syscall.Stat_t{Uid: 231072, Gid: 231072},
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
			h:       h,
			args:    args{r, 1002},
			want:    &syscall.Stat_t{Uid: 0, Gid: 0},
			wantErr: true,
			prepare: func() {

				// Create proc entry in mem-based FS.
				afero.WriteFile(sysio.AppFs, "/proc/1001/ns/pid", []byte("123456"), 0644)
			},
		},
		//
		// Commenting out test-case 3 for now till we're done with issue-147.
		//
		// {
		// 	//
		// 	// Test-case 3: Missing a container matching the pid-ns-inode associated
		// 	//              to the pid of the incoming request. Error expected.
		// 	//
		// 	name:    "3",
		// 	h:       h,
		// 	args:    args{r, 1001},
		// 	want:    &syscall.Stat_t{Uid: 0, Gid: 0},
		// 	wantErr: true,
		// 	prepare: func() {

		// 		// Create proc entry in mem-based FS.
		// 		afero.WriteFile(sysio.AppFs, "/proc/1001/ns/pid", []byte("1111"), 0644)
		// 	},
		// },
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

			// Run function to test.
			got, err := tt.h.Getattr(tt.args.n, tt.args.pid)
			if (err != nil) != tt.wantErr {
				t.Errorf("CommonHandler.Getattr() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Ensure results match expectations.
			if tt.wantErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestCommonHandler_Read(t *testing.T) {

	//
	// Test-cases common attributes.
	//
	var css = state.NewContainerStateService()
	var ios = sysio.NewIOService(sysio.IOFileService)
	var nss = &mocks.NSenterService{}

	var hds = handler.NewHandlerService(handler.DefaultHandlers, css, nss, ios)

	// Handler to test.
	var h1 = &implementations.CommonHandler{
		Name:    "common",
		Path:    "commonHandler",
		Service: hds,
	}

	// Resource to read().
	var r = ios.NewIOnode("net", "/proc/sys/net", 0)

	// Create new container and add it to the containerDB.
	cntr := css.ContainerCreate("cntr-1", 1001, "syscntr1", 123456, time.Time{}, 0, 0, 0, 0)
	err := css.ContainerAdd(cntr)
	if err != nil {
		return
	}

	//
	// Test-case definitions.
	//
	type args struct {
		n   domain.IOnode
		pid uint32
		buf []byte
		off int64
	}
	tests := []struct {
		name    string
		h       *implementations.CommonHandler
		args    args
		want    int
		wantErr bool
		prepare func(m *mocks.NSenterService)
	}{
		{
			//
			// Test-case 1: Regular read() operation. No errors expected.
			//
			name:    "1",
			h:       h1,
			args:    args{r, 1001, make([]byte, len("123456")+1), 0},
			want:    len("123456") + 1,
			wantErr: false,
			prepare: func(m *mocks.NSenterService) {

				// Create proc entry in mem-based FS.
				afero.WriteFile(sysio.AppFs, "/proc/1001/ns/pid", []byte("123456"), 0644)

				expectedResponse := &nsenter.NSenterEvent{
					Resource:  "/proc/sys/net",
					Pid:       1001,
					Namespace: []domain.NStype{string(domain.NStypeNet)},
					ReqMsg: &domain.NSenterMessage{
						Type:    domain.ReadFileRequest,
						Payload: "",
					},
					ResMsg: &domain.NSenterMessage{
						Type:    domain.ReadFileResponse,
						Payload: "123456",
					},
				}

				nss.On("NewEvent", "/proc/sys/net", uint32(1001),
					[]domain.NStype{string(domain.NStypeNet)},
					expectedResponse.ReqMsg,
					(*domain.NSenterMessage)(nil)).Return(expectedResponse)

				nss.On("LaunchEvent", expectedResponse).Return(nil)

				nss.On("ResponseEvent", expectedResponse).Return(expectedResponse.ResMsg)
			},
		},
		{
			//
			// Test-case 2: Missing pid-ns-inode for the pid associated to the
			//              incoming request. IOW, no pid-ns is found for this
			//              container. Error expected.
			//
			name:    "2",
			h:       h1,
			args:    args{r, 1002, make([]byte, len("123456")+1), 0},
			want:    0,
			wantErr: true,
			prepare: func(m *mocks.NSenterService) {

				// Create proc entry in mem-based FS.
				afero.WriteFile(sysio.AppFs, "/proc/1001/ns/pid", []byte("123456"), 0644)
			},
		},
		{
			//
			// Test-case 3: Missing a container matching the pid-ns-inode associated
			//              to the pid of the incoming request. Error expected.
			//
			name:    "3",
			h:       h1,
			args:    args{r, 1001, make([]byte, len("123456")+1), 0},
			want:    0,
			wantErr: true,
			prepare: func(m *mocks.NSenterService) {

				// Create proc entry in mem-based FS.
				afero.WriteFile(sysio.AppFs, "/proc/1001/ns/pid", []byte("11111"), 0644)
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
				tt.prepare(nss)
			}

			// Run function to test.
			got, err := tt.h.Read(tt.args.n, tt.args.pid, tt.args.buf, tt.args.off)
			if (err != nil) != tt.wantErr {
				t.Errorf("CommonHandler.Read() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("CommonHandler.Read() = %v, want %v", got, tt.want)
			}

			// Ensure results match expectations.
			if tt.wantErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
				assert.Equal(t, tt.want, got)
			}

			// Ensure that mocks were properly invoked.
			nss.AssertExpectations(t)
		})
	}
}

func TestCommonHandler_Write(t *testing.T) {

	//
	// Test-cases common attributes.
	//
	var css = state.NewContainerStateService()
	var ios = sysio.NewIOService(sysio.IOFileService)
	var nss = &mocks.NSenterService{}

	var hds = handler.NewHandlerService(handler.DefaultHandlers, css, nss, ios)

	// Handler to test.
	var h1 = &implementations.CommonHandler{
		Name:    "common",
		Path:    "commonHandler",
		Service: hds,
	}

	// Resource to write().
	var r = ios.NewIOnode("net", "/proc/sys/net", 0)

	// Create new container and add it to the containerDB.
	cntr := css.ContainerCreate("cntr-1", 1001, "syscntr1", 123456, time.Time{}, 0, 0, 0, 0)
	err := css.ContainerAdd(cntr)
	if err != nil {
		return
	}

	//
	// Test-case definitions.
	//
	type args struct {
		n   domain.IOnode
		pid uint32
		buf []byte
	}
	tests := []struct {
		name    string
		h       *implementations.CommonHandler
		args    args
		want    int
		wantErr bool
		prepare func(m *mocks.NSenterService)
	}{
		{
			//
			// Test-case 1: Regular write operation. No errors expected.
			//
			name:    "1",
			h:       h1,
			args:    args{r, 1001, []byte("123456")},
			want:    len("123456"),
			wantErr: false,
			prepare: func(m *mocks.NSenterService) {

				// Create proc entry in mem-based FS.
				afero.WriteFile(sysio.AppFs, "/proc/1001/ns/pid", []byte("123456"), 0644)

				expectedResponse := &nsenter.NSenterEvent{
					Resource:  "/proc/sys/net",
					Pid:       1001,
					Namespace: []domain.NStype{string(domain.NStypeNet)},
					ReqMsg: &domain.NSenterMessage{
						Type:    domain.WriteFileRequest,
						Payload: "123456"},
					ResMsg: &domain.NSenterMessage{
						Type:    domain.WriteFileResponse,
						Payload: "",
					},
				}

				nss.On("NewEvent", "/proc/sys/net", uint32(1001),
					[]domain.NStype{string(domain.NStypeNet)},
					expectedResponse.ReqMsg,
					(*domain.NSenterMessage)(nil)).Return(expectedResponse)

				nss.On("LaunchEvent", expectedResponse).Return(nil)

				nss.On("ResponseEvent", expectedResponse).Return(expectedResponse.ResMsg)
			},
		},
		{
			//
			// Test-case 2: Missing pid-ns-inode for the pid associated to the
			//              incoming request. IOW, no pid-ns is found for this
			//              container. Error expected.
			//
			name:    "2",
			h:       h1,
			args:    args{r, 1002, []byte("123456")},
			want:    0,
			wantErr: true,
			prepare: func(m *mocks.NSenterService) {

				// Create proc entry in mem-based FS.
				afero.WriteFile(sysio.AppFs, "/proc/1001/ns/pid", []byte("123456"), 0644)
			},
		},
		{
			//
			// Test-case 3: Missing a container matching the pid-ns-inode associated
			//              to the pid of the incoming request. Error expected.
			//
			name:    "3",
			h:       h1,
			args:    args{r, 1001, []byte("123456")},
			want:    0,
			wantErr: true,
			prepare: func(m *mocks.NSenterService) {

				// Create proc entry in mem-based FS.
				afero.WriteFile(sysio.AppFs, "/proc/1001/ns/pid", []byte("11111"), 0644)
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
				tt.prepare(nss)
			}

			// Run function to test.
			got, err := tt.h.Write(tt.args.n, tt.args.pid, tt.args.buf)
			if (err != nil) != tt.wantErr {
				t.Errorf("CommonHandler.Write() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("CommonHandler.Write() = %v, want %v", got, tt.want)
			}

			// Ensure results match expectations.
			if tt.wantErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
				assert.Equal(t, tt.want, got)
			}

			// Ensure that mocks were properly invoked.
			nss.AssertExpectations(t)
		})
	}
}

func TestCommonHandler_ReadDirAll(t *testing.T) {

	//
	// Test-cases common attributes.
	//
	var css = state.NewContainerStateService()
	var ios = sysio.NewIOService(sysio.IOFileService)
	var nss = &mocks.NSenterService{}

	var hds = handler.NewHandlerService(handler.DefaultHandlers, css, nss, ios)

	// Handler to test.
	var h1 = &implementations.CommonHandler{
		Name:    "common",
		Path:    "commonHandler",
		Service: hds,
	}

	// Resource to read().
	var r = ios.NewIOnode("net", "/proc/sys/net", 0)

	// Create new container and add it to the containerDB.
	cntr := css.ContainerCreate("cntr-1", 1001, "syscntr1", 123456, time.Time{}, 0, 0, 0, 0)
	err := css.ContainerAdd(cntr)
	if err != nil {
		return
	}

	//
	// Test-case definitions.
	//
	type args struct {
		n   domain.IOnode
		pid uint32
	}
	tests := []struct {
		name    string
		h       *implementations.CommonHandler
		args    args
		want    []os.FileInfo
		wantErr bool
		prepare func(m *mocks.NSenterService)
	}{
		{
			//
			// Test-case 1: Regular read() operation. No errors expected.
			//
			name: "1",
			h:    h1,
			args: args{r, 1001},
			want: []os.FileInfo{
				domain.FileInfo{
					Fname: "/proc/sys/net/bridge",
				},
				domain.FileInfo{
					Fname: "/proc/sys/net/core",
				},
				domain.FileInfo{
					Fname: "/proc/sys/net/ipv4",
				},
				domain.FileInfo{
					Fname: "/proc/sys/net/ipv6",
				},
				domain.FileInfo{
					Fname: "/proc/sys/net/netfilter",
				},
			},
			wantErr: false,
			prepare: func(m *mocks.NSenterService) {

				// Create proc entry in mem-based FS.
				afero.WriteFile(sysio.AppFs, "/proc/1001/ns/pid", []byte("123456"), 0644)

				expectedResponse := &nsenter.NSenterEvent{
					Resource:  "/proc/sys/net",
					Pid:       1001,
					Namespace: []domain.NStype{string(domain.NStypeNet)},
					ReqMsg: &domain.NSenterMessage{
						Type:    domain.ReadDirRequest,
						Payload: "",
					},
					ResMsg: &domain.NSenterMessage{
						Type: domain.ReadDirResponse,
						Payload: []domain.FileInfo{
							domain.FileInfo{
								Fname: "/proc/sys/net/bridge",
							},
							domain.FileInfo{
								Fname: "/proc/sys/net/core",
							},
							domain.FileInfo{
								Fname: "/proc/sys/net/ipv4",
							},
							domain.FileInfo{
								Fname: "/proc/sys/net/ipv6",
							},
							domain.FileInfo{
								Fname: "/proc/sys/net/netfilter",
							},
						},
					},
				}

				nss.On("NewEvent", "/proc/sys/net", uint32(1001),
					[]domain.NStype{string(domain.NStypeNet)},
					expectedResponse.ReqMsg,
					(*domain.NSenterMessage)(nil)).Return(expectedResponse)

				nss.On("LaunchEvent", expectedResponse).Return(nil)

				nss.On("ResponseEvent", expectedResponse).Return(expectedResponse.ResMsg)
			},
		},
		{
			//
			// Test-case 2: Missing pid-ns-inode for the pid associated to the
			//              incoming request. IOW, no pid-ns is found for this
			//              container. Error expected.
			//
			name:    "2",
			h:       h1,
			args:    args{r, 1002},
			want:    nil,
			wantErr: true,
			prepare: func(m *mocks.NSenterService) {

				// Create proc entry in mem-based FS.
				afero.WriteFile(sysio.AppFs, "/proc/1001/ns/pid", []byte("123456"), 0644)
			},
		},
		{
			//
			// Test-case 3: Missing a container matching the pid-ns-inode associated
			//              to the pid of the incoming request. Error expected.
			//
			name:    "3",
			h:       h1,
			args:    args{r, 1001},
			want:    nil,
			wantErr: true,
			prepare: func(m *mocks.NSenterService) {

				// Create proc entry in mem-based FS.
				afero.WriteFile(sysio.AppFs, "/proc/1001/ns/pid", []byte("11111"), 0644)
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
				tt.prepare(nss)
			}

			// Run function to test.
			got, err := tt.h.ReadDirAll(tt.args.n, tt.args.pid)
			if (err != nil) != tt.wantErr {
				t.Errorf("CommonHandler.ReadDirAll() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Ensure results match expectations.
			if tt.wantErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
				assert.Equal(t, tt.want, got)
			}

			// Ensure that mocks were properly invoked.
			nss.AssertExpectations(t)
		})
	}
}

func TestCommonHandler_EmulatedFilesInfo(t *testing.T) {

	//
	// Test-cases common attributes.
	//
	var css = state.NewContainerStateService()
	var ios = sysio.NewIOService(sysio.IOFileService)
	var nss = &mocks.NSenterService{}

	var hds = handler.NewHandlerService(handler.DefaultHandlers, css, nss, ios)

	// Handler to test.
	var h = &implementations.CommonHandler{
		Name:    "common",
		Path:    "commonHandler",
		Service: hds,
	}

	// Resource where to run a ReadDirAll() on, which will be the caller of
	// this function being tested (EmulatedFilesInfo).
	var r = ios.NewIOnode("net", "/proc/sys/net/netfilter", 0)

	// Create new container and add it to the containerDB.
	cntr := css.ContainerCreate("cntr-1", 1001, "syscntr1", 123456, time.Time{}, 0, 0, 0, 0)
	err := css.ContainerAdd(cntr)
	if err != nil {
		return
	}

	//
	// Test-case definitions.
	//
	type args struct {
		n   domain.IOnode
		pid uint32
	}
	tests := []struct {
		name    string
		h       *implementations.CommonHandler
		args    args
		want    []os.FileInfo
		prepare func()
	}{
		{
			//
			// Test-case 1: Regular lookup operation. No errors expected.
			//
			name: "1",
			h:    h,
			args: args{r, 1001},
			want: []os.FileInfo{domain.FileInfo{Fname: "nf_conntrack_max"}},
			prepare: func() {

				// Create proc entry in mem-based FS.
				afero.WriteFile(sysio.AppFs, "/proc/1001/ns/pid", []byte("123456"), 0644)

				// Create proc entry in mem-based FS corresponding to the emulated
				// resource to be looked up.
				afero.WriteFile(sysio.AppFs, "/proc/sys/net/netfilter/nf_conntrack_max", []byte("123456"), 0)
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

			// Run function to test.
			got := tt.h.EmulatedFilesInfo(tt.args.n, tt.args.pid)

			// Verify that the content of the obtained slice matches the expected one.
			for i := 0; i < len(got); i++ {
				if got[i].Name() != tt.want[i].Name() || got[i].Mode() != tt.want[i].Mode() {
					t.Errorf("received Name() = %v, Mode() = %v, want Name() = %v, Mode = %v",
						got[i].Name(), got[i].Mode(), tt.want[i].Name(), tt.want[i].Mode())
				}
			}
		})
	}
}

func TestCommonHandler_FetchFile(t *testing.T) {

	//
	// Test-cases common attributes.
	//
	var css = state.NewContainerStateService()
	var ios = sysio.NewIOService(sysio.IOFileService)
	var nss = &mocks.NSenterService{}

	var hds = handler.NewHandlerService(handler.DefaultHandlers, css, nss, ios)

	// Handler to test.
	var h1 = &implementations.CommonHandler{
		Name:    "common",
		Path:    "commonHandler",
		Service: hds,
	}

	// Resource to read().
	var r = ios.NewIOnode("net", "/proc/sys/net", 0)

	// Create new container and add it to the containerDB.
	cntr := css.ContainerCreate("cntr-1", 1001, "syscntr1", 123456, time.Time{}, 0, 0, 0, 0)
	err := css.ContainerAdd(cntr)
	if err != nil {
		return
	}

	//
	// Test-case definitions.
	//
	type args struct {
		n domain.IOnode
		c domain.ContainerIface
	}
	tests := []struct {
		name    string
		h       *implementations.CommonHandler
		args    args
		want    string
		wantErr bool
		prepare func(m *mocks.NSenterService)
	}{
		{
			//
			// Test-case 1: Regular read() operation. No errors expected.
			//
			name:    "1",
			h:       h1,
			args:    args{r, cntr},
			want:    "123456",
			wantErr: false,
			prepare: func(m *mocks.NSenterService) {

				expectedResponse := &nsenter.NSenterEvent{
					Resource:  "/proc/sys/net",
					Pid:       1001,
					Namespace: []domain.NStype{string(domain.NStypeNet)},
					ReqMsg: &domain.NSenterMessage{
						Type:    domain.ReadFileRequest,
						Payload: "",
					},
					ResMsg: &domain.NSenterMessage{
						Type:    domain.ReadFileResponse,
						Payload: "123456",
					},
				}

				nss.On("NewEvent", "/proc/sys/net", uint32(1001),
					[]domain.NStype{string(domain.NStypeNet)},
					expectedResponse.ReqMsg,
					(*domain.NSenterMessage)(nil)).Return(expectedResponse)

				nss.On("LaunchEvent", expectedResponse).Return(nil)

				nss.On("ResponseEvent", expectedResponse).Return(expectedResponse.ResMsg)
			},
		},
	}

	//
	// Testcase executions.
	//
	for _, tt := range tests {

		t.Run(tt.name, func(t *testing.T) {

			// Prepare the mocks.
			if tt.prepare != nil {
				tt.prepare(nss)
			}

			// Run function to test.
			got, err := tt.h.FetchFile(tt.args.n, tt.args.c)
			if (err != nil) != tt.wantErr {
				t.Errorf("CommonHandler.FetchFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("CommonHandler.FetchFile() = %v, want %v", got, tt.want)
			}

			// Ensure results match expectations.
			if tt.wantErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
				assert.Equal(t, tt.want, got)
			}

			// Ensure that mocks were properly invoked.
			nss.AssertExpectations(t)
		})
	}
}

func TestCommonHandler_PushFile(t *testing.T) {

	//
	// Test-cases common attributes.
	//
	var css = state.NewContainerStateService()
	var ios = sysio.NewIOService(sysio.IOFileService)
	var nss = &mocks.NSenterService{}

	var hds = handler.NewHandlerService(handler.DefaultHandlers, css, nss, ios)

	// Handler to test.
	var h1 = &implementations.CommonHandler{
		Name:    "common",
		Path:    "commonHandler",
		Service: hds,
	}

	// Resource to write().
	var r = ios.NewIOnode("net", "/proc/sys/net", 0)

	// Create new container and add it to the containerDB.
	cntr := css.ContainerCreate("cntr-1", 1001, "syscntr1", 123456, time.Time{}, 0, 0, 0, 0)
	err := css.ContainerAdd(cntr)
	if err != nil {
		return
	}

	//
	// Test-case definitions.
	//
	type args struct {
		n domain.IOnode
		c domain.ContainerIface
		s string
	}
	tests := []struct {
		name    string
		h       *implementations.CommonHandler
		args    args
		want    error
		wantErr bool
		prepare func(m *mocks.NSenterService)
	}{
		{
			//
			// Test-case 1: Regular push (write) operation. No errors expected.
			//
			name:    "1",
			h:       h1,
			args:    args{r, cntr, "123456"},
			want:    nil,
			wantErr: false,
			prepare: func(m *mocks.NSenterService) {

				expectedResponse := &nsenter.NSenterEvent{
					Resource:  "/proc/sys/net",
					Pid:       1001,
					Namespace: []domain.NStype{string(domain.NStypeNet)},
					ReqMsg: &domain.NSenterMessage{
						Type:    domain.WriteFileRequest,
						Payload: "123456"},
					ResMsg: &domain.NSenterMessage{
						Type:    domain.WriteFileResponse,
						Payload: "",
					},
				}

				nss.On("NewEvent", "/proc/sys/net", uint32(1001),
					[]domain.NStype{string(domain.NStypeNet)},
					expectedResponse.ReqMsg,
					(*domain.NSenterMessage)(nil)).Return(expectedResponse)

				nss.On("LaunchEvent", expectedResponse).Return(nil)

				nss.On("ResponseEvent", expectedResponse).Return(expectedResponse.ResMsg)
			},
		},
	}

	//
	// Testcase executions.
	//
	for _, tt := range tests {

		t.Run(tt.name, func(t *testing.T) {

			// Prepare the mocks.
			if tt.prepare != nil {
				tt.prepare(nss)
			}

			// Run function to test.
			err := tt.h.PushFile(tt.args.n, tt.args.c, tt.args.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("CommonHandler.PushFile() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != tt.want {
				t.Errorf("CommonHandler.PushFile() = %v, want %v", err, tt.want)
			}

			// Ensure results match expectations.
			if tt.wantErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
				assert.Equal(t, tt.want, err)
			}

			// Ensure that mocks were properly invoked.
			nss.AssertExpectations(t)
		})
	}
}

func TestCommonHandler_GetName(t *testing.T) {

	//
	// Test-cases common attributes.
	//
	var css = state.NewContainerStateService()
	var ios = sysio.NewIOService(sysio.IOFileService)
	var nss = &mocks.NSenterService{}

	var hds = handler.NewHandlerService(handler.DefaultHandlers, css, nss, ios)

	// Handler to test.
	var h = &implementations.CommonHandler{
		Name:    "common",
		Path:    "commonHandler",
		Service: hds,
	}

	//
	// Test-case definitions.
	//
	tests := []struct {
		name string
		h    *implementations.CommonHandler
		want string
	}{
		{"1", h, "common"},
	}

	//
	// Testcase executions.
	//
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.h.GetName(); got != tt.want {
				t.Errorf("CommonHandler.GetName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCommonHandler_GetPath(t *testing.T) {

	//
	// Test-cases common attributes.
	//
	var css = state.NewContainerStateService()
	var ios = sysio.NewIOService(sysio.IOFileService)
	var nss = &mocks.NSenterService{}

	var hds = handler.NewHandlerService(handler.DefaultHandlers, css, nss, ios)

	// Handler to test.
	var h = &implementations.CommonHandler{
		Name:    "common",
		Path:    "commonHandler",
		Service: hds,
	}

	//
	// Test-case definitions.
	//
	tests := []struct {
		name string
		h    *implementations.CommonHandler
		want string
	}{
		{"1", h, "commonHandler"},
	}

	//
	// Testcase executions.
	//
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.h.GetPath(); got != tt.want {
				t.Errorf("CommonHandler.GetPath() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCommonHandler_GetEnabled(t *testing.T) {

	//
	// Test-cases common attributes.
	//
	var css = state.NewContainerStateService()
	var ios = sysio.NewIOService(sysio.IOFileService)
	var nss = &mocks.NSenterService{}

	var hds = handler.NewHandlerService(handler.DefaultHandlers, css, nss, ios)

	// Handler to test.
	var h = &implementations.CommonHandler{
		Name:    "common",
		Path:    "commonHandler",
		Enabled: true,
		Service: hds,
	}

	//
	// Test-case definitions.
	//
	tests := []struct {
		name string
		h    *implementations.CommonHandler
		want bool
	}{
		{"1", h, true},
	}

	//
	// Testcase executions.
	//
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.h.GetEnabled(); got != tt.want {
				t.Errorf("CommonHandler.GetEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCommonHandler_GetService(t *testing.T) {

	//
	// Test-cases common attributes.
	//
	var css = state.NewContainerStateService()
	var ios = sysio.NewIOService(sysio.IOFileService)
	var nss = &mocks.NSenterService{}

	var hds = handler.NewHandlerService(handler.DefaultHandlers, css, nss, ios)

	// Handler to test.
	var h = &implementations.CommonHandler{
		Name:    "common",
		Path:    "commonHandler",
		Service: hds,
	}

	//
	// Test-case definitions.
	//
	tests := []struct {
		name string
		h    *implementations.CommonHandler
		want domain.HandlerService
	}{
		{"1", h, hds},
	}

	//
	// Testcase executions.
	//
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.h.GetService(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CommonHandler.GetService() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCommonHandler_SetEnabled(t *testing.T) {

	//
	// Test-cases common attributes.
	//
	var css = state.NewContainerStateService()
	var ios = sysio.NewIOService(sysio.IOFileService)
	var nss = &mocks.NSenterService{}

	var hds = handler.NewHandlerService(handler.DefaultHandlers, css, nss, ios)

	// Handler to test.
	var h = &implementations.CommonHandler{
		Name:    "common",
		Path:    "commonHandler",
		Service: hds,
	}

	//
	// Test-case definitions.
	//
	type args struct {
		val bool
	}
	tests := []struct {
		name string
		h    *implementations.CommonHandler
		args args
	}{
		{"1", h, args{true}},
	}

	//
	// Testcase executions.
	//
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.h.SetEnabled(tt.args.val)
		})
	}
}

func TestCommonHandler_SetService(t *testing.T) {

	//
	// Test-cases common attributes.
	//
	var css = state.NewContainerStateService()
	var ios = sysio.NewIOService(sysio.IOFileService)
	var nss = &mocks.NSenterService{}

	var hds = handler.NewHandlerService(handler.DefaultHandlers, css, nss, ios)

	// Handler to test.
	var h = &implementations.CommonHandler{
		Name:    "common",
		Path:    "commonHandler",
		Service: hds,
	}

	//
	// Test-case definitions.
	//
	type args struct {
		hs domain.HandlerService
	}
	tests := []struct {
		name string
		h    *implementations.CommonHandler
		args args
	}{
		{"1", h, args{hds}},
	}

	//
	// Testcase executions.
	//
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.h.SetService(tt.args.hs)
		})
	}
}
