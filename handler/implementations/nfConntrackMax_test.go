//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

package implementations_test

import (
	"os"
	"reflect"
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

func TestNfConntrackMaxHandler_Lookup(t *testing.T) {

	//
	// Test-cases common attributes.
	//
	var css = state.NewContainerStateService()
	var ios = sysio.NewIOService(sysio.IOFileService)
	var nss = &mocks.NSenterService{}

	var hds = handler.NewHandlerService(handler.DefaultHandlers, css, nss, ios)

	// Handler to test.
	var h = &implementations.NfConntrackMaxHandler{
		Name:    "nfConntrackMax",
		Path:    "/proc/sys/net/netfilter/nf_conntrack_max",
		Service: hds,
	}

	// Resource to Lookup().
	var r = ios.NewIOnode("nf_conntrack_max", "/proc/sys/net/netfilter/nf_conntrack_max", 0)

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
		h       *implementations.NfConntrackMaxHandler
		args    args
		want    os.FileInfo
		wantErr bool
		prepare func()
	}{
		{
			name: "1",
			h:    h,
			args: args{r, 1001},
			want: &domain.FileInfo{Fname: "nf_conntrack_max", Fmode: 0644},
			prepare: func() {

				// Create proc entry in mem-based FS.
				afero.WriteFile(sysio.AppFs, "/proc/1001/ns/pid", []byte("123456"), 0644)

				// Create proc entry in mem-based FS corresponding to the emulated
				// resource to be looked up.
				afero.WriteFile(
					sysio.AppFs,
					"/proc/sys/net/netfilter/nf_conntrack_max",
					[]byte("123456"),
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
				t.Errorf("NfConntrackMaxHandler.Lookup() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if got.Name() != tt.want.Name() || got.Mode() != tt.want.Mode() {
				t.Errorf("received Name() = %v, Mode() = %v, want Name() = %v, Mode = %v",
					got.Name(), got.Mode(), tt.want.Name(), tt.want.Mode())
			}
		})
	}
}

func TestNfConntrackMaxHandler_Getattr(t *testing.T) {

	//
	// Test-cases common attributes.
	//
	var css = state.NewContainerStateService()
	var ios = sysio.NewIOService(sysio.IOFileService)
	var nss = &mocks.NSenterService{}

	var hds = handler.NewHandlerService(handler.DefaultHandlers, css, nss, ios)

	// Handler to test.
	var h = &implementations.NfConntrackMaxHandler{
		Name:    "nfConntrackMax",
		Path:    "/proc/sys/net/netfilter/nf_conntrack_max",
		Service: hds,
	}

	// Resource to Lookup().
	var r = ios.NewIOnode("nf_conntrack_max", "/proc/sys/net/netfilter/nf_conntrack_max", 0)

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
		h       *implementations.NfConntrackMaxHandler
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
				t.Errorf("NfConntrackMaxHandler.Getattr() error = %v, wantErr %v", err, tt.wantErr)
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

func TestNfConntrackMaxHandler_Open(t *testing.T) {

	//
	// Test-cases common attributes.
	//
	var css = state.NewContainerStateService()
	var ios = sysio.NewIOService(sysio.IOFileService)
	var nss = &mocks.NSenterService{}

	var hds = handler.NewHandlerService(handler.DefaultHandlers, css, nss, ios)

	// Handler to test.
	var h = &implementations.NfConntrackMaxHandler{
		Name:    "nfConntrackMax",
		Path:    "/proc/sys/net/netfilter/nf_conntrack_max",
		Service: hds,
	}

	// Resource to Open().
	var r = ios.NewIOnode("nf_conntrack_max", "/proc/sys/net/netfilter/nf_conntrack_max", 0)

	//
	// Test-case definitions.
	//
	type args struct {
		n domain.IOnode
		pid uint32
	}
	tests := []struct {
		name    string
		h       *implementations.NfConntrackMaxHandler
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
			args:    args{r, 123},
			wantErr: false,
			prepare: func() {

				// Create proc entry in mem-based FS.
				afero.WriteFile(
					sysio.AppFs,
					"/proc/sys/net/netfilter/nf_conntrack_max",
					[]byte(""),
					0644,
				)
			},
		},
		{
			//
			// Test-case 2: Attempt to open() a non-existing file. Error expected.
			//
			name:    "2",
			h:       h,
			args:    args{r, 123},
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
			args:    args{r, 123},
			wantErr: true,
			prepare: func() {

				// Create proc entry in mem-based FS.
				afero.WriteFile(
					sysio.AppFs,
					"/proc/sys/net/netfilter/nf_conntrack_max",
					[]byte(""),
					0644,
				)

				// Remove expected syscall.O_RDONLY and O_WRONLY flags.
				r.SetOpenFlags(syscall.O_RDWR)
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
				t.Errorf("NfConntrackMaxHandler.Open() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNfConntrackMaxHandler_Close(t *testing.T) {
	type args struct {
		n domain.IOnode
	}
	tests := []struct {
		name    string
		h       *implementations.NfConntrackMaxHandler
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.h.Close(tt.args.n); (err != nil) != tt.wantErr {
				t.Errorf("NfConntrackMaxHandler.Close() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNfConntrackMaxHandler_Read(t *testing.T) {

	//
	// Test-cases common attributes.
	//
	var css = state.NewContainerStateService()
	var ios = sysio.NewIOService(sysio.IOFileService)
	var nss = &mocks.NSenterService{}

	var hds = handler.NewHandlerService(handler.DefaultHandlers, css, nss, ios)

	// Handler to test.
	var h = &implementations.NfConntrackMaxHandler{
		Name:    "nfConntrackMax",
		Path:    "/proc/sys/net/netfilter/nf_conntrack_max",
		Service: hds,
	}

	// Resource to Lookup().
	var r = ios.NewIOnode("nf_conntrack_max", "/proc/sys/net/netfilter/nf_conntrack_max", 0)

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
		h       *implementations.NfConntrackMaxHandler
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
			args:    args{r, 1001, make([]byte, len("65535")+1), 0},
			want:    len("65535") + 1,
			wantErr: false,
			prepare: func() {

				// Create proc entry in mem-based FS.
				afero.WriteFile(sysio.AppFs, "/proc/1001/ns/pid", []byte("123456"), 0644)

				// Create proc entry in mem-based FS corresponding to the emulated
				// resource to be read.
				afero.WriteFile(
					sysio.AppFs,
					"/proc/sys/net/netfilter/nf_conntrack_max",
					[]byte("65535"),
					0644,
				)
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
			args:    args{r, 1002, make([]byte, len("65535")+1), 0},
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
			args:    args{r, 1001, make([]byte, len("123456")+1), 0},
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
			args:    args{r, 1001, make([]byte, len("65535")+1), 0},
			want:    len("65535") + 1,
			wantErr: false,
			prepare: func() {

				// Create proc entry in mem-based FS.
				afero.WriteFile(sysio.AppFs, "/proc/1001/ns/pid", []byte("123456"), 0644)

				// Create proc entry in mem-based FS corresponding to the emulated
				// resource to be read.
				afero.WriteFile(
					sysio.AppFs,
					"/proc/sys/net/netfilter/nf_conntrack_max",
					[]byte("655356"),
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

			// Run function to test.
			got, err := tt.h.Read(tt.args.n, tt.args.pid, tt.args.buf, tt.args.off)
			if (err != nil) != tt.wantErr {
				t.Errorf("NfConntrackMaxHandler.Read() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("NfConntrackMaxHandler.Read() = %v, want %v", got, tt.want)
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

func TestNfConntrackMaxHandler_Write(t *testing.T) {
	t.Skip("Skipping write testcase temporarily")
	//
	// Test-cases common attributes.
	//
	var css = state.NewContainerStateService()
	var ios = sysio.NewIOService(sysio.IOFileService)
	var nss = &mocks.NSenterService{}

	var hds = handler.NewHandlerService(handler.DefaultHandlers, css, nss, ios)

	// Handler to test.
	var h = &implementations.NfConntrackMaxHandler{
		Name:    "nfConntrackMax",
		Path:    "/proc/sys/net/netfilter/nf_conntrack_max",
		Service: hds,
	}

	// Resource to Lookup().
	var r = ios.NewIOnode("nf_conntrack_max", "/proc/sys/net/netfilter/nf_conntrack_max", 0)

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
		h       *implementations.NfConntrackMaxHandler
		args    args
		want    int
		wantErr bool
		prepare func()
	}{
		{
			//
			// Test-case 1: Regular write operation. No errors expected.
			//
			name:    "1",
			h:       h,
			args:    args{r, 1001, []byte("655356")},
			want:    len("655356"),
			wantErr: false,
			prepare: func() {

				// Create proc entry in mem-based FS.
				afero.WriteFile(sysio.AppFs, "/proc/1001/ns/pid", []byte("123456"), 0644)

				// Create proc entry in mem-based FS corresponding to the emulated
				// resource to be read.
				afero.WriteFile(
					sysio.AppFs,
					"/proc/sys/net/netfilter/nf_conntrack_max",
					[]byte("65535"),
					0644,
				)

				// Open nf_conntrack_max's associated sysio construct. See that
				// this routine must be invoked to ensure that resource is opened
				// with RDWR permissions.
				_ = h.Open(r, 1001)
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
			args:    args{r, 1002, []byte("65535")},
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
			//              to the pid of the incoming request. Error expected.
			//
			name:    "3",
			h:       h,
			args:    args{r, 1001, []byte("65535")},
			want:    0,
			wantErr: true,
			prepare: func() {

				// Create proc entry in mem-based FS.
				afero.WriteFile(sysio.AppFs, "/proc/1001/ns/pid", []byte("11111"), 0644)
			},
		},
		{
			//
			// Test-case 4: Write smaller value than the existing one. No data
			// should be written to the FS.
			//
			name:    "4",
			h:       h,
			args:    args{r, 1001, []byte("6553")},
			want:    len("6553"),
			wantErr: false,
			prepare: func() {

				// Create proc entry in mem-based FS.
				afero.WriteFile(sysio.AppFs, "/proc/1001/ns/pid", []byte("123456"), 0644)

				// Create proc entry in mem-based FS corresponding to the emulated
				// resource to be read.
				afero.WriteFile(
					sysio.AppFs,
					"/proc/sys/net/netfilter/nf_conntrack_max",
					[]byte("65535"),
					0644,
				)
			},
		},
		{
			//
			// Test-case 5: Write larger value than the existing one. New value
			// should be written to cache and FS.
			//
			name:    "5",
			h:       h,
			args:    args{r, 1001, []byte("655356")},
			want:    len("655356"),
			wantErr: false,
			prepare: func() {

				// Create proc entry in mem-based FS.
				afero.WriteFile(sysio.AppFs, "/proc/1001/ns/pid", []byte("123456"), 0644)

				// Create proc entry in mem-based FS corresponding to the emulated
				// resource to be read.
				afero.WriteFile(
					sysio.AppFs,
					"/proc/sys/net/netfilter/nf_conntrack_max",
					[]byte("65535"),
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

			// Run function to test.
			got, err := tt.h.Write(tt.args.n, tt.args.pid, tt.args.buf)
			if (err != nil) != tt.wantErr {
				t.Errorf("NfConntrackMaxHandler.Write() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("NfConntrackMaxHandler.Write() = %v, want %v", got, tt.want)
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

func TestNfConntrackMaxHandler_ReadDirAll(t *testing.T) {
	type args struct {
		n   domain.IOnode
		pid uint32
	}
	tests := []struct {
		name    string
		h       *implementations.NfConntrackMaxHandler
		args    args
		want    []os.FileInfo
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.h.ReadDirAll(tt.args.n, tt.args.pid)
			if (err != nil) != tt.wantErr {
				t.Errorf("NfConntrackMaxHandler.ReadDirAll() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NfConntrackMaxHandler.ReadDirAll() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNfConntrackMaxHandler_FetchFile(t *testing.T) {
	type args struct {
		n domain.IOnode
		c domain.ContainerIface
	}
	tests := []struct {
		name    string
		h       *implementations.NfConntrackMaxHandler
		args    args
		want    string
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.h.FetchFile(tt.args.n, tt.args.c)
			if (err != nil) != tt.wantErr {
				t.Errorf("NfConntrackMaxHandler.fetch() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("NfConntrackMaxHandler.fetch() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNfConntrackMaxHandler_PushFile(t *testing.T) {
	type args struct {
		n         domain.IOnode
		c         domain.ContainerIface
		newMaxInt int
	}
	tests := []struct {
		name    string
		h       *implementations.NfConntrackMaxHandler
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.h.PushFile(tt.args.n, tt.args.c, tt.args.newMaxInt); (err != nil) != tt.wantErr {
				t.Errorf("NfConntrackMaxHandler.push() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNfConntrackMaxHandler_GetName(t *testing.T) {
	tests := []struct {
		name string
		h    *implementations.NfConntrackMaxHandler
		want string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.h.GetName(); got != tt.want {
				t.Errorf("NfConntrackMaxHandler.GetName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNfConntrackMaxHandler_GetPath(t *testing.T) {
	tests := []struct {
		name string
		h    *implementations.NfConntrackMaxHandler
		want string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.h.GetPath(); got != tt.want {
				t.Errorf("NfConntrackMaxHandler.GetPath() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNfConntrackMaxHandler_GetEnabled(t *testing.T) {
	tests := []struct {
		name string
		h    *implementations.NfConntrackMaxHandler
		want bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.h.GetEnabled(); got != tt.want {
				t.Errorf("NfConntrackMaxHandler.GetEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNfConntrackMaxHandler_GetService(t *testing.T) {
	tests := []struct {
		name string
		h    *implementations.NfConntrackMaxHandler
		want domain.HandlerServiceIface
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.h.GetService(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NfConntrackMaxHandler.GetService() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNfConntrackMaxHandler_SetEnabled(t *testing.T) {
	type args struct {
		val bool
	}
	tests := []struct {
		name string
		h    *implementations.NfConntrackMaxHandler
		args args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.h.SetEnabled(tt.args.val)
		})
	}
}

func TestNfConntrackMaxHandler_SetService(t *testing.T) {
	type args struct {
		hs domain.HandlerServiceIface
	}
	tests := []struct {
		name string
		h    *implementations.NfConntrackMaxHandler
		args args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.h.SetService(tt.args.hs)
		})
	}
}
