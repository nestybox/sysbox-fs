package seccomp

import (
	"fmt"
	"reflect"
	"syscall"
	"testing"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
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

// dispatchNSenter fakes the nsenter service: it records the requests that
// sysbox-fs sends and answers each of them with resp.
type dispatchNSenter struct {
	domain.NSenterServiceIface
	reqs []*domain.NSenterMessage
	resp *domain.NSenterMessage
}

type dispatchEvent struct {
	domain.NSenterEventIface
	req *domain.NSenterMessage
}

func (n *dispatchNSenter) NewEvent(pid, uid, gid uint32, ns *[]domain.NStype,
	cloneFlags uint32, req, res *domain.NSenterMessage, async bool) domain.NSenterEventIface {
	return &dispatchEvent{req: req}
}

func (n *dispatchNSenter) SendRequestEvent(e domain.NSenterEventIface) error {
	n.reqs = append(n.reqs, e.(*dispatchEvent).req)
	return nil
}

func (n *dispatchNSenter) ReceiveResponseEvent(domain.NSenterEventIface) *domain.NSenterMessage {
	return n.resp
}

func dispatchRequest(flags uint64, fstype string) (*mountSyscallInfo, *dispatchMountService) {
	mts := mount.NewMountService()
	mts.Setup(nil, dispatchHandler{}, nil, nil)
	svc := &dispatchMountService{helper: mts.NewMountHelper()}
	nss := &dispatchNSenter{resp: &domain.NSenterMessage{Type: domain.MountSyscallResponse}}
	tracer := &syscallTracer{service: &SyscallMonitorService{mts: svc, nss: nss}}
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
		direct bool
	}{
		{"move", unix.MS_MOVE, 0, false},
		{"propagation", unix.MS_PRIVATE, 0, false},
		{"bind-before-move", unix.MS_BIND | unix.MS_MOVE, 1, false},
		{"bind-before-propagation", unix.MS_BIND | unix.MS_PRIVATE, 1, false},
		{"new-with-magic", unix.MS_MGC_VAL, 1, false},
		{"remount-readonly", unix.MS_REMOUNT | unix.MS_BIND | unix.MS_RDONLY | unix.MS_MOVE, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, svc := dispatchRequest(tc.flags, "ext4")
			nss := m.tracer.service.nss.(*dispatchNSenter)
			got, err := m.process()

			// An authorized remount is executed by sysbox-fs (never resumed
			// via CONTINUE); every other path is left to the kernel.
			want := m.tracer.createContinueResponse(m.reqId)
			wantReqs := 0
			if tc.direct {
				want = m.tracer.createSuccessResponse(m.reqId)
				wantReqs = 1
			}

			if err != nil || !reflect.DeepEqual(got, want) || svc.parses != tc.parses || len(nss.reqs) != wantReqs {
				t.Fatalf("unexpected dispatch: response=%+v error=%v parses=%d nsenter-requests=%d",
					got, err, svc.parses, len(nss.reqs))
			}

			// The nsenter request must carry the arguments that were
			// validated, not a second read of the tracee's memory.
			if tc.direct {
				payload := *nss.reqs[0].Payload.(*[]*domain.MountSyscallPayload)
				if len(payload) != 1 || payload[0] != m.MountSyscallPayload {
					t.Fatalf("nsenter request does not carry the validated mount payload: %+v", payload)
				}
			}
		})
	}
}

func TestMountRemountDirectError(t *testing.T) {
	m, _ := dispatchRequest(unix.MS_REMOUNT|unix.MS_BIND|unix.MS_RDONLY, "ext4")
	nss := m.tracer.service.nss.(*dispatchNSenter)
	nss.resp = &domain.NSenterMessage{
		Type:    domain.ErrorResponse,
		Payload: fuse.IOerror{Code: syscall.EACCES},
	}

	got, err := m.process()
	want := m.tracer.createErrorResponse(m.reqId, syscall.EACCES)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("remount failure not reported to the tracee: response=%+v error=%v", got, err)
	}
}
