package fuse

import (
	"io/ioutil"
	"log"
	"reflect"
	"testing"

	"bazil.org/fuse/fs"
	_ "bazil.org/fuse/fs/fstestutil"
	"github.com/nestybox/sysvisor/sysvisor-fs/domain"
	"github.com/nestybox/sysvisor/sysvisor-fs/handler"
	"github.com/nestybox/sysvisor/sysvisor-fs/nsenter"
	"github.com/nestybox/sysvisor/sysvisor-fs/state"
	"github.com/nestybox/sysvisor/sysvisor-fs/sysio"
	"github.com/spf13/afero"
)

func TestMain(m *testing.M) {

	// Disable log generation during UT.
	log.SetOutput(ioutil.Discard)

	m.Run()
}
func TestNewFuseService(t *testing.T) {

	var css = state.NewContainerStateService()
	var ios = sysio.NewIOService(sysio.IOFileService)
	var nss = nsenter.NewNSenterService()
	var hds = handler.NewHandlerService(handler.DefaultHandlers, css, nss, ios)

	// Test definition.
	type args struct {
		path       string
		mountPoint string
		ios        domain.IOService
		hds        domain.HandlerService
	}
	tests := []struct {
		name string
		args args
		want domain.FuseService
	}{
		// Invalid mountpoint.
		{"1", args{"/", "/var/lib/non-existing", ios, hds}, nil},

		// Invalid FS path.
		{"2", args{"/non-existing", "/var/lib/sysvisorfs", ios, hds}, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewFuseService(tt.args.path, tt.args.mountPoint, tt.args.ios, tt.args.hds)

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewFuseService() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Skipping this test for now as we need to fix the lack of permission
// issue that prevents non-root users from being able to fuse-mount
// into /var/lib/sysvisorfs folder.
func Test_fuseService_Run(t *testing.T) {

	// Skipping this one for now.
	t.Skip("Skipping fuseService.Runc() for now")

	var css = state.NewContainerStateService()
	var ios = sysio.NewIOService(sysio.IOFileService)
	var nss = nsenter.NewNSenterService()
	var hds = handler.NewHandlerService(handler.DefaultHandlers, css, nss, ios)

	// Initialize memory-based mock FS.
	sysio.AppFs = afero.NewMemMapFs()

	// Create proc entries in mem-based FS.
	sysio.AppFs.MkdirAll("/", 0777)
	sysio.AppFs.MkdirAll("/var/lib/sysvisorfs", 0777)

	// Create a new FuseService.
	var fuseSvc = NewFuseService("/", "/var/lib/sysvisorfs", ios, hds)

	// Test definition.
	tests := []struct {
		name    string
		s       *fuseService
		wantErr bool
	}{
		{"1", fuseSvc.(*fuseService), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.s.Run(); (err != nil) != tt.wantErr {
				t.Errorf("fuseService.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_fuseService_Root(t *testing.T) {
	tests := []struct {
		name    string
		s       *fuseService
		want    fs.Node
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.Root()
			if (err != nil) != tt.wantErr {
				t.Errorf("fuseService.Root() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("fuseService.Root() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_fuseService_MountPoint(t *testing.T) {
	tests := []struct {
		name string
		s    *fuseService
		want string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.s.MountPoint(); got != tt.want {
				t.Errorf("fuseService.MountPoint() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_fuseService_Unmount(t *testing.T) {
	tests := []struct {
		name string
		s    *fuseService
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.s.Unmount()
		})
	}
}
