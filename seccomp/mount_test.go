package seccomp

import (
	"fmt"
	"reflect"
	"syscall"
	"testing"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/mount"
	"golang.org/x/sys/unix"
)

// Embed unused interfaces so unexpected dispatch paths fail the test instead
// of being silently accepted by a permissive mock.
type dispatchProcess struct{ domain.ProcessIface }

func (dispatchProcess) MountNsInode() (domain.Inode, error) { return 1, nil }
func (dispatchProcess) RootInode() uint64                   { return 2 }
func (dispatchProcess) Root() string                        { return "/" }

type dispatchContainer struct{ domain.ContainerIface }

func (dispatchContainer) IsMountInfoInitialized() bool  { return true }
func (dispatchContainer) InitProc() domain.ProcessIface { return dispatchProcess{} }
func (dispatchContainer) IsImmutableRoMountID(int) bool { return true }

type dispatchParser struct{ domain.MountInfoParserIface }

func (dispatchParser) IsSysboxfsBaseMount(string) bool  { return false }
func (dispatchParser) IsSysboxfsSubmount(string) bool   { return false }
func (dispatchParser) IsRoMount(*domain.MountInfo) bool { return true }
func (dispatchParser) GetInfo(string) *domain.MountInfo { return &domain.MountInfo{MountID: 10} }

type dispatchMountService struct {
	domain.MountServiceIface
	helper domain.MountHelperIface
	parses int
}

type dispatchHandler struct{ domain.HandlerServiceIface }

func (s *dispatchMountService) MountHelper() domain.MountHelperIface { return s.helper }
func (s *dispatchMountService) NewMountInfoParser(domain.ContainerIface, domain.ProcessIface, bool, bool, bool) (domain.MountInfoParserIface, error) {
	s.parses++
	return dispatchParser{}, nil
}

func dispatchRequest(flags uint64, fstype string) (*mountSyscallInfo, *dispatchMountService) {
	mts := mount.NewMountService()
	mts.Setup(nil, dispatchHandler{}, nil, nil)
	svc := &dispatchMountService{helper: mts.NewMountHelper()}
	tracer := &syscallTracer{service: &SyscallMonitorService{mts: svc}}
	m := &mountSyscallInfo{
		syscallCtx: syscallCtx{
			reqId: 42, root: "/", cntr: dispatchContainer{},
			processInfo: dispatchProcess{}, tracer: tracer,
		},
		MountSyscallPayload: &domain.MountSyscallPayload{
			Mount: domain.Mount{Source: "/source", Target: "/protected", FsType: fstype, Flags: flags},
		},
	}
	return m, svc
}

func TestMountRemountPrecedence(t *testing.T) {
	extra := []uint64{unix.MS_MOVE, unix.MS_SHARED, unix.MS_PRIVATE, unix.MS_SLAVE, unix.MS_UNBINDABLE}
	for mask := 0; mask < 1<<len(extra); mask++ {
		flags := uint64(unix.MS_REMOUNT)
		for i, flag := range extra {
			if mask&(1<<i) != 0 {
				flags |= flag
			}
		}
		for _, bind := range []uint64{0, unix.MS_BIND} {
			for _, magic := range []uint64{0, unix.MS_MGC_VAL} {
				for _, fstype := range []string{"", "proc", "sysfs"} {
					f := flags | bind | magic
					t.Run(fmt.Sprintf("%x/%s", f, fstype), func(t *testing.T) {
						m, svc := dispatchRequest(f, fstype)
						got, err := m.process()
						want := m.tracer.createErrorResponse(m.reqId, syscall.EPERM)
						if err != nil || !reflect.DeepEqual(got, want) || svc.parses != 1 {
							t.Fatalf("immutable remount bypassed authorization: response=%+v error=%v parses=%d", got, err, svc.parses)
						}
					})
				}
			}
		}
	}
}

func TestMountDispatchControls(t *testing.T) {
	for _, tc := range []struct {
		name   string
		flags  uint64
		parses int
	}{
		{"move", unix.MS_MOVE, 0},
		{"propagation", unix.MS_PRIVATE, 0},
		{"bind-before-move", unix.MS_BIND | unix.MS_MOVE, 1},
		{"bind-before-propagation", unix.MS_BIND | unix.MS_PRIVATE, 1},
		{"new-with-magic", unix.MS_MGC_VAL, 1},
		{"remount-readonly", unix.MS_REMOUNT | unix.MS_BIND | unix.MS_RDONLY | unix.MS_MOVE, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, svc := dispatchRequest(tc.flags, "ext4")
			got, err := m.process()
			want := m.tracer.createContinueResponse(m.reqId)
			if err != nil || !reflect.DeepEqual(got, want) || svc.parses != tc.parses {
				t.Fatalf("unexpected dispatch: response=%+v error=%v parses=%d", got, err, svc.parses)
			}
		})
	}
}
