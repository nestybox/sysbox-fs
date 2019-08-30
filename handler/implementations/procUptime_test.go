//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

package implementations_test

import (
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/handler"
	"github.com/nestybox/sysbox-fs/handler/implementations"
	"github.com/nestybox/sysbox-fs/mocks"
	"github.com/nestybox/sysbox-fs/state"
	"github.com/nestybox/sysbox-fs/sysio"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
)

func TestProcUptimeHandler_Lookup(t *testing.T) {

	//
	// Test-cases common attributes.
	//
	var css = state.NewContainerStateService()
	var ios = sysio.NewIOService(sysio.IOFileService)
	var nss = &mocks.NSenterService{}

	var hds = handler.NewHandlerService(handler.DefaultHandlers, css, nss, ios)

	// Handler to test.
	var h = &implementations.ProcUptimeHandler{
		Name:    "procUptime",
		Path:    "/proc/uptime",
		Service: hds,
	}

	// Resource to Lookup().
	var r = ios.NewIOnode("uptime", "/proc/uptime", 0)

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
		h       *implementations.ProcUptimeHandler
		args    args
		want    os.FileInfo
		wantErr bool
		prepare func()
	}{
		{
			name: "1",
			h:    h,
			args: args{r, 1001},
			want: &domain.FileInfo{Fname: "uptime", Fmode: 0644},
			prepare: func() {

				// Create proc entry in mem-based FS.
				afero.WriteFile(sysio.AppFs, "/proc/1001/ns/pid", []byte("123456"), 0644)

				// Create proc entry in mem-based FS corresponding to the emulated
				// resource to be looked up.
				afero.WriteFile(
					sysio.AppFs,
					"/proc/uptime",
					[]byte("60.00 60.00"),
					0644,
				)
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

			got, err := tt.h.Lookup(tt.args.n, tt.args.pid)
			if (err != nil) != tt.wantErr {
				t.Errorf("ProcUptimeHandler.Lookup() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if got.Name() != tt.want.Name() || got.Mode() != tt.want.Mode() {
				t.Errorf("received Name() = %v, Mode() = %v, want Name() = %v, Mode = %v",
					got.Name(), got.Mode(), tt.want.Name(), tt.want.Mode())
			}
		})
	}
}

func TestProcUptimeHandler_Getattr(t *testing.T) {

	//
	// Test-cases common attributes.
	//
	var css = state.NewContainerStateService()
	var ios = sysio.NewIOService(sysio.IOFileService)
	var nss = &mocks.NSenterService{}

	var hds = handler.NewHandlerService(handler.DefaultHandlers, css, nss, ios)

	// Handler to test.
	var h = &implementations.ProcUptimeHandler{
		Name:    "procUptime",
		Path:    "/proc/uptime",
		Service: hds,
	}

	// Resource to Lookup().
	var r = ios.NewIOnode("uptime", "/proc/uptime", 0)

	// Create new container and add it to the containerDB.
	cntr := css.ContainerCreate(
		"cntr-1",
		1001,
		"syscntr1",
		123456,
		time.Time{},
		231072,
		65536,
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
		h       *implementations.ProcUptimeHandler
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
				t.Errorf("ProcUptimeHandler.Getattr() error = %v, wantErr %v", err, tt.wantErr)
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

func TestProcUptimeHandler_Open(t *testing.T) {

	//
	// Test-cases common attributes.
	//
	var css = state.NewContainerStateService()
	var ios = sysio.NewIOService(sysio.IOFileService)
	var nss = &mocks.NSenterService{}

	var hds = handler.NewHandlerService(handler.DefaultHandlers, css, nss, ios)

	// Handler to test.
	var h = &implementations.ProcUptimeHandler{
		Name:    "procUptime",
		Path:    "/proc/uptime",
		Service: hds,
	}

	// Resource to Open().
	var r = ios.NewIOnode("uptime", "/proc/uptime", 0)

	//
	// Test-case definitions.
	//
	type args struct {
		n domain.IOnode
		pid uint32
	}
	tests := []struct {
		name    string
		h       *implementations.ProcUptimeHandler
		args    args
		wantErr bool
		prepare func()
	}{
		{
			//
			// Test-case 1: Regular open() operation. No errors expected.
			//
			name:    "1",
			h:       h,
			args:    args{r, 1001},
			wantErr: false,
			prepare: func() {

				// Create proc entry in mem-based FS.
				afero.WriteFile(sysio.AppFs, "/proc/uptime", []byte(""), 0644)
			},
		},
		{
			//
			// Test-case 2: Attempt to open() a non-existing file. Error expected.
			//
			name:    "2",
			h:       h,
			args:    args{r, 1001},
			wantErr: true,
			prepare: func() {

				// Create proc entry in mem-based FS.
				afero.WriteFile(sysio.AppFs, "/proc/non-existing", []byte(""), 0644)
			},
		},
		{
			//
			// Test-case 3: Attempt to open() file when this one is missing expected
			// openflags. Error expected.
			//
			name:    "3",
			h:       h,
			args:    args{r, 1001},
			wantErr: true,
			prepare: func() {

				// Create proc entry in mem-based FS.
				afero.WriteFile(sysio.AppFs, "/proc/uptime", []byte(""), 0644)

				// Remove expected syscall.O_RDONLY flag (default flag).
				r.SetOpenFlags(syscall.O_WRONLY)
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

			if err := tt.h.Open(tt.args.n, tt.args.pid); (err != nil) != tt.wantErr {
				t.Errorf("ProcUptimeHandler.Open() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestProcUptimeHandler_Read(t *testing.T) {

	//
	// Test-cases common attributes.
	//
	var css = state.NewContainerStateService()
	var ios = sysio.NewIOService(sysio.IOFileService)
	var nss = &mocks.NSenterService{}

	var hds = handler.NewHandlerService(handler.DefaultHandlers, css, nss, ios)

	// Handler to test.
	var h = &implementations.ProcUptimeHandler{
		Name:    "procUptime",
		Path:    "/proc/uptime",
		Service: hds,
	}

	// Resource to Read().
	var r = ios.NewIOnode("uptime", "/proc/uptime", 0)

	// Create new container and add it to the containerDB.
	cntr := css.ContainerCreate(
		"cntr-1",
		1001,
		"syscntr1",
		123456,
		time.Now().AddDate(0, 0, -1), // current-time minus one day
		231072,
		65536,
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
		buf []byte
		off int64
	}
	tests := []struct {
		name    string
		h       *implementations.ProcUptimeHandler
		args    args
		want    int
		wantErr bool
		prepare func()
	}{
		{
			//
			// Test-case 1: Regular read() operation. No errors expected.
			//
			name:    "1",
			h:       h,
			args:    args{r, 1001, make([]byte, len("86400.00 86400.00")+1), 0},
			want:    len("86400.00 86400.00") + 1,
			wantErr: false,
			prepare: func() {

				// Create proc entry in mem-based FS.
				afero.WriteFile(sysio.AppFs, "/proc/1001/ns/pid", []byte("123456"), 0644)
			},
		},
		{
			//
			// Test-case 2: Missing pid-ns-inode for the pid associated to the
			// incoming request. IOW, no pid-ns is found for this container.
			// Error expected.
			//
			name:    "2",
			h:       h,
			args:    args{r, 1002, make([]byte, len("86400.00 86400.00")+1), 0},
			want:    0,
			wantErr: true,
			prepare: func() {

				// Create proc entry in mem-based FS.
				afero.WriteFile(sysio.AppFs, "/proc/1001/ns/pid", []byte("123456"), 0644)
			},
		},
		{
			//
			// Test-case 3: Missing a container matching the pid-ns-inode associated
			// to the pid of the incoming request. Error expected.
			//
			name:    "3",
			h:       h,
			args:    args{r, 1001, make([]byte, len("86400.00 86400.00")+1), 0},
			want:    0,
			wantErr: true,
			prepare: func() {

				// Create proc entry in mem-based FS.
				afero.WriteFile(sysio.AppFs, "/proc/1001/ns/pid", []byte("11111"), 0644)
			},
		},
		{
			//
			// Test-case 4: Verify that subsequent read operations are served
			// directly from cache, and that no further I/O is triggered. Notice
			// to confirm this point i'm modifying nf_conntrack_max in the host
			// FS, and yet, the expected result is still the old/previous one.
			//
			name:    "4",
			h:       h,
			args:    args{r, 1001, make([]byte, len("86400.00 86400.00")+1), 0},
			want:    len("86400.00 86400.00") + 1,
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

			// Run function to test.
			got, err := tt.h.Read(tt.args.n, tt.args.pid, tt.args.buf, tt.args.off)
			if (err != nil) != tt.wantErr {
				t.Errorf("ProcUptimeHandler.Read() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ProcUptimeHandler.Read() = %v, want %v", got, tt.want)
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
