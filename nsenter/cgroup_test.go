//
// Copyright 2019-2023 Nestybox, Inc.
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

package nsenter

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
	"github.com/nestybox/sysbox-runc/libcontainer/cgroups"
	"golang.org/x/sys/unix"
)

// TestMain re-executes this test binary as the nsenter agent, the same way
// sysbox-fs does with its own binary ("<binary> nsenter", see
// cmd/sysbox-fs/main.go). This lets the end-to-end tests below exercise
// SendRequest() for real.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "nsenter" {
		if err := Init(); err != nil {
			fmt.Fprintf(os.Stderr, "nsenter: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	os.Exit(m.Run())
}

// fixtureMounts maps cgroup controllers to directories under root, mirroring
// the mountFn contract ("" is the unified hierarchy).
func fixtureMounts(root string) mountFn {
	m := map[string]string{
		"":        filepath.Join(root, "unified"),
		"devices": filepath.Join(root, "v1", "devices"),
		"freezer": filepath.Join(root, "v1", "freezer"),
	}

	return func(controller string) (string, error) {
		if p, ok := m[controller]; ok {
			return p, nil
		}
		return "", fmt.Errorf("no mount for controller %q", controller)
	}
}

// writeFile creates parent directories and writes content to path.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestResolveDeviceCgroup(t *testing.T) {

	tests := []struct {
		name       string
		procCgroup string
		wantDir    string // relative to the mount for the entry's controller
		wantFreez  string // relative to the freezer mount, "" if none
		wantErr    bool
	}{
		{
			name:       "cgroup v2 unified entry",
			procCgroup: "0::/user.slice/app.scope\n",
			wantDir:    "unified/user.slice/app.scope",
		},
		{
			name:       "cgroup v2 root",
			procCgroup: "0::/\n",
			wantDir:    "unified",
		},
		{
			name: "hybrid host: v1 devices is authoritative over unified entry",
			procCgroup: "12:devices:/docker/abc\n" +
				"11:freezer:/docker/abc\n" +
				"1:name=systemd:/docker/abc\n" +
				"0::/system.slice/c.service\n",
			wantDir:   "v1/devices/docker/abc",
			wantFreez: "v1/freezer/docker/abc",
		},
		{
			name:       "cgroup v1 devices without freezer",
			procCgroup: "4:devices:/a/b\n3:cpu,cpuacct:/a/b\n",
			wantDir:    "v1/devices/a/b",
		},
		{
			name:       "no device cgroup listed",
			procCgroup: "3:cpu,cpuacct:/a/b\n",
			wantErr:    true,
		},
		{
			name:       "malformed entry",
			procCgroup: "garbage\n",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "cgroup")
			writeFile(t, path, tt.procCgroup)

			dc, err := resolveDeviceCgroup(path, fixtureMounts(root))
			if (err != nil) != tt.wantErr {
				t.Fatalf("resolveDeviceCgroup() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if want := filepath.Join(root, tt.wantDir); dc.dir != want {
				t.Errorf("dir = %s, want %s", dc.dir, want)
			}

			wantFreezer := ""
			if tt.wantFreez != "" {
				wantFreezer = filepath.Join(root, tt.wantFreez)
			}
			if dc.freezerDir != wantFreezer {
				t.Errorf("freezerDir = %q, want %q", dc.freezerDir, wantFreezer)
			}
		})
	}
}

func TestDeviceCgroupFrozen(t *testing.T) {

	tests := []struct {
		name    string
		files   map[string]string // relative to the cgroup dir ("v2") or freezer dir ("v1")
		v1      bool
		frozen  bool
		wantErr bool
	}{
		{
			name:   "v2 thawed",
			files:  map[string]string{"cgroup.events": "populated 1\nfrozen 0\n", "cgroup.freeze": "0\n"},
			frozen: false,
		},
		{
			name:   "v2 frozen effectively (e.g., via a frozen ancestor)",
			files:  map[string]string{"cgroup.events": "populated 1\nfrozen 1\n", "cgroup.freeze": "0\n"},
			frozen: true,
		},
		{
			name:   "v2 freeze requested",
			files:  map[string]string{"cgroup.events": "populated 1\nfrozen 0\n", "cgroup.freeze": "1\n"},
			frozen: true,
		},
		{
			name:   "v2 without freeze files is not frozen",
			files:  map[string]string{},
			frozen: false,
		},
		{
			name:   "v1 freezer thawed",
			files:  map[string]string{"freezer.state": "THAWED\n"},
			v1:     true,
			frozen: false,
		},
		{
			name:   "v1 freezer frozen",
			files:  map[string]string{"freezer.state": "FROZEN\n"},
			v1:     true,
			frozen: true,
		},
		{
			name:   "v1 freezer freezing",
			files:  map[string]string{"freezer.state": "FREEZING\n"},
			v1:     true,
			frozen: true,
		},
		{
			name:    "v1 freezer state unreadable fails closed",
			files:   map[string]string{},
			v1:      true,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			dc := deviceCgroup{dir: filepath.Join(root, "unified", "x")}
			if tt.v1 {
				dc = deviceCgroup{
					dir:        filepath.Join(root, "v1", "devices", "x"),
					freezerDir: filepath.Join(root, "v1", "freezer", "x"),
				}
			}
			for name, content := range tt.files {
				dir := dc.dir
				if tt.v1 {
					dir = dc.freezerDir
				}
				writeFile(t, filepath.Join(dir, name), content)
			}

			got, err := dc.frozen()
			if (err != nil) != tt.wantErr {
				t.Fatalf("frozen() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.frozen {
				t.Errorf("frozen() = %v, want %v", got, tt.frozen)
			}
		})
	}
}

func TestRequesterDeviceCgroup(t *testing.T) {

	root := t.TempDir()
	procRoot := filepath.Join(root, "proc")
	mount := fixtureMounts(root)

	// A thawed requester in the unified hierarchy.
	writeFile(t, filepath.Join(procRoot, "100", "cgroup"), "0::/ctr/app\n")
	writeFile(t, filepath.Join(root, "unified", "ctr", "app", "cgroup.events"), "populated 1\nfrozen 0\n")

	// A requester whose cgroup is frozen.
	writeFile(t, filepath.Join(procRoot, "101", "cgroup"), "0::/ctr/paused\n")
	writeFile(t, filepath.Join(root, "unified", "ctr", "paused", "cgroup.events"), "populated 1\nfrozen 1\n")

	t.Run("thawed requester resolves to its cgroup", func(t *testing.T) {
		dc, err := requesterDeviceCgroup(100, procRoot, mount)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if want := filepath.Join(root, "unified", "ctr", "app"); dc.dir != want {
			t.Errorf("dir = %s, want %s", dc.dir, want)
		}
	})

	t.Run("frozen requester is rejected", func(t *testing.T) {
		_, err := requesterDeviceCgroup(101, procRoot, mount)
		if !errors.Is(err, errCgroupFrozen) {
			t.Fatalf("error = %v, want errCgroupFrozen", err)
		}
	})

	t.Run("unknown requester pid fails closed", func(t *testing.T) {
		if _, err := requesterDeviceCgroup(999, procRoot, mount); err == nil {
			t.Fatal("expected an error for a pid without /proc entry")
		}
	})
}

func TestDeviceCgroupJoin(t *testing.T) {

	root := t.TempDir()
	dir := filepath.Join(root, "unified", "ctr", "app")
	writeFile(t, filepath.Join(dir, "cgroup.procs"), "")

	dc := deviceCgroup{dir: dir}
	if err := dc.join(4242); err != nil {
		t.Fatalf("join() unexpected error: %v", err)
	}

	b, err := os.ReadFile(filepath.Join(dir, "cgroup.procs"))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "4242" {
		t.Errorf("cgroup.procs = %q, want %q", string(b), "4242")
	}

	// A missing cgroup must be an error, never a silent no-op.
	missing := deviceCgroup{dir: filepath.Join(root, "does-not-exist")}
	if err := missing.join(4242); err == nil {
		t.Error("join() into a missing cgroup must fail")
	}
}

func TestCgroupJoinErrorDeniesWithEPERM(t *testing.T) {
	cause := errors.New("cannot join")
	err := cgroupJoinError(cause)

	ioerr, ok := err.(fuse.IOerror)
	if !ok {
		t.Fatalf("cgroupJoinError() = %T, want fuse.IOerror", err)
	}
	if ioerr.Code != syscall.EPERM {
		t.Errorf("Code = %v, want EPERM", ioerr.Code)
	}
	if !errors.Is(ioerr.RcvError, cause) {
		t.Errorf("RcvError does not wrap the cause")
	}
}

// ownDeviceCgroup returns the device cgroup of the test process.
func ownDeviceCgroup(t *testing.T) deviceCgroup {
	t.Helper()
	dc, err := resolveDeviceCgroup("/proc/self/cgroup", defaultCgroupMount)
	if err != nil {
		t.Skipf("cannot resolve own device cgroup: %v", err)
	}
	return dc
}

// setupRequesterCgroup creates a child cgroup under the test process's own
// cgroup and moves a sleeping process into it. It skips the test when the host
// does not delegate cgroups to the test user.
func setupRequesterCgroup(t *testing.T) (requester *exec.Cmd, childDir string) {
	t.Helper()

	if !cgroups.IsCgroup2UnifiedMode() {
		t.Skip("end-to-end join requires cgroup v2")
	}

	own := ownDeviceCgroup(t)

	childDir, err := os.MkdirTemp(own.dir, "sysbox-fs-join-test-")
	if err != nil {
		t.Skipf("cannot create a child cgroup under %s (not delegated?): %v", own.dir, err)
	}

	requester = exec.Command("sleep", "60")
	if err := requester.Start(); err != nil {
		os.Remove(childDir)
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = requester.Process.Kill()
		_ = requester.Wait()
		// Removal fails while processes remain; they are gone by now.
		_ = os.Remove(childDir)
	})

	if err := cgroups.WriteCgroupProc(childDir, requester.Process.Pid); err != nil {
		t.Skipf("cannot move a process into %s: %v", childDir, err)
	}

	return requester, childDir
}

// requireAgentCaps skips the test unless the test process holds CAP_SYS_ADMIN
// and CAP_SYS_RESOURCE, which the nsexec agent needs even when it joins no
// namespace: it lowers oom_score_adj and sets up its namespaces. Without them
// the agent exits before it reports its child, so the test cannot run.
func requireAgentCaps(t *testing.T) {
	t.Helper()

	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		t.Skipf("cannot read capabilities: %v", err)
	}

	for _, c := range []int{unix.CAP_SYS_ADMIN, unix.CAP_SYS_RESOURCE} {
		if data[c/32].Effective&(1<<(c%32)) == 0 {
			t.Skipf("nsexec agent needs CAP_SYS_ADMIN and CAP_SYS_RESOURCE (capability %d not effective)", c)
		}
	}
}

// agentRead performs a ReadFileRequest through the nsenter agent. The clone
// flags follow the payload's mounts, as in passThrough.go; nss is the set of
// namespaces to join and may be empty.
func agentRead(pid uint32, join bool, payload *domain.ReadFilePayload, nss []domain.NStype) ([]byte, error) {
	service := NewNSenterService()

	// The agent remounts procfs/sysfs in its own mount namespace.
	cloneFlags := uint32(0)
	if payload.MountProcfs || payload.MountSysfs {
		cloneFlags = unix.CLONE_NEWNS
	}

	event := service.NewEvent(
		pid,
		0,
		0,
		&nss,
		cloneFlags,
		&domain.NSenterMessage{
			Type:    domain.ReadFileRequest,
			Payload: payload,
		},
		nil,
		false,
	)
	event.SetJoinRequesterCgroup(join)

	if err := service.SendRequestEvent(event); err != nil {
		return nil, err
	}

	resp := service.ReceiveResponseEvent(event)
	if resp.Type == domain.ErrorResponse {
		return nil, resp.Payload.(error)
	}

	return resp.Payload.([]byte), nil
}

// agentCgroupPath returns the unified cgroup path (as listed in
// /proc/<pid>/cgroup) of the nsenter agent dispatched for pid. The agent reads
// /proc/self/cgroup, so the answer reflects the cgroup it ran in.
func agentCgroupPath(t *testing.T, pid uint32, join bool) (string, error) {
	t.Helper()

	// The agent joins no namespace, so /proc/self/cgroup is relative to the
	// test's own cgroup namespace, as ownPath is.
	data, err := agentRead(pid, join,
		&domain.ReadFilePayload{
			File: "/proc/self/cgroup",
			Len:  4096,
		},
		[]domain.NStype{})
	if err != nil {
		return "", err
	}

	tmp := filepath.Join(t.TempDir(), "cgroup")
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		t.Fatal(err)
	}

	entries, err := cgroups.ParseCgroupFile(tmp)
	if err != nil {
		t.Fatal(err)
	}

	return entries[""], nil
}

// TestSendRequestWithoutNamespaces checks that an agent given no namespace to
// join still reads: nsexec rejects an empty NS_PATHS attribute, so the attribute
// must be omitted. Skips without CAP_SYS_ADMIN and CAP_SYS_RESOURCE.
func TestSendRequestWithoutNamespaces(t *testing.T) {
	requireAgentCaps(t)

	file := filepath.Join(t.TempDir(), "content")
	writeFile(t, file, "no namespaces\n")

	data, err := agentRead(uint32(os.Getpid()), false,
		&domain.ReadFilePayload{File: file, Len: 4096},
		[]domain.NStype{})
	if err != nil {
		t.Fatalf("read with no namespaces failed: %v", err)
	}
	if string(data) != "no namespaces\n" {
		t.Errorf("read = %q, want %q", data, "no namespaces\n")
	}
}

// TestSendRequestJoinsRequesterCgroup checks that the agent runs in the cgroup
// of the requesting process, and only when asked to.
func TestSendRequestJoinsRequesterCgroup(t *testing.T) {

	requester, _ := setupRequesterCgroup(t)

	requesterCgroup, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", requester.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	reqPath := strings.TrimSpace(strings.TrimPrefix(string(requesterCgroup), "0::"))

	ownPath := strings.TrimPrefix(strings.Split(readFileOrFail(t, "/proc/self/cgroup"), "\n")[0], "0::")

	// Joined: the agent runs in the requester's cgroup, so the kernel evaluates
	// the requester's device policy for whatever the agent reads.
	got, err := agentCgroupPath(t, uint32(requester.Process.Pid), true)
	if err != nil {
		t.Fatalf("join request failed: %v", err)
	}
	if got != reqPath {
		t.Errorf("agent cgroup with join = %q, want requester's %q", got, reqPath)
	}

	// Not joined: the agent stays in sysbox-fs's (here, the test's) cgroup.
	got, err = agentCgroupPath(t, uint32(requester.Process.Pid), false)
	if err != nil {
		t.Fatalf("plain request failed: %v", err)
	}
	if got != ownPath {
		t.Errorf("agent cgroup without join = %q, want %q", got, ownPath)
	}
}

// TestSendRequestJoinDeniesFrozenRequester checks that a frozen requester is
// refused before any agent is dispatched, with EPERM.
func TestSendRequestJoinDeniesFrozenRequester(t *testing.T) {

	requester, childDir := setupRequesterCgroup(t)

	writeFile(t, filepath.Join(childDir, "cgroup.freeze"), "1")
	defer func() { _ = os.WriteFile(filepath.Join(childDir, "cgroup.freeze"), []byte("0"), 0644) }()

	_, err := agentCgroupPath(t, uint32(requester.Process.Pid), true)
	ioerr, ok := err.(fuse.IOerror)
	if !ok {
		t.Fatalf("error = %T (%v), want fuse.IOerror", err, err)
	}
	if ioerr.Code != syscall.EPERM {
		t.Errorf("Code = %v, want EPERM", ioerr.Code)
	}
	if !errors.Is(ioerr.RcvError, errCgroupFrozen) {
		t.Errorf("cause = %v, want errCgroupFrozen", ioerr.RcvError)
	}
}

// TestSendRequestJoinDeniesUnknownRequester checks that a request for a pid
// that does not exist is denied, instead of read unconfined.
func TestSendRequestJoinDeniesUnknownRequester(t *testing.T) {
	if _, err := os.Stat("/proc/self/cgroup"); err != nil {
		t.Skip("no procfs")
	}

	_, err := agentCgroupPath(t, 0x7ffffff0, true)
	ioerr, ok := err.(fuse.IOerror)
	if !ok || ioerr.Code != syscall.EPERM {
		t.Fatalf("error = %v, want EPERM", err)
	}
}

// TestSendRequestJoinBoundsStalledAgent checks that an agent that never
// answers does not hold the request forever. The read blocks on a FIFO with no
// writer, which is the stall a freezer produces.
func TestSendRequestJoinBoundsStalledAgent(t *testing.T) {

	requester, _ := setupRequesterCgroup(t)

	prev := cgroupJoinResponseTimeout
	cgroupJoinResponseTimeout = 300 * time.Millisecond
	defer func() { cgroupJoinResponseTimeout = prev }()

	fifo := filepath.Join(t.TempDir(), "stall")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	_, err := agentRead(uint32(requester.Process.Pid), true,
		&domain.ReadFilePayload{File: fifo, Len: 4096},
		[]domain.NStype{})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected the stalled request to fail")
	}
	// It must have waited for the bound (not failed immediately), and must not
	// wait unboundedly.
	if elapsed < 300*time.Millisecond {
		t.Errorf("stalled request failed after %v, before the response timeout", elapsed)
	}
	if elapsed > 10*time.Second {
		t.Errorf("stalled request took %v; the response wait is not bounded", elapsed)
	}
}

func readFileOrFail(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestJoinRequesterCgroupGatesKfdRead is an opt-in check against a real host
// with an AMD KFD device. It verifies that the kernel's device-cgroup gate on
// GPU topology applies to a read dispatched for a requester:
//
//	SYSBOX_FS_TEST_DENIED_PID  pid of a process whose device cgroup does not
//	                           grant the GPU (e.g., started by a plain
//	                           "docker run" without --device); its read must
//	                           fail with EPERM.
//	SYSBOX_FS_TEST_GRANTED_PID pid of a process whose device cgroup grants the
//	                           GPU (e.g., "docker run --device /dev/kfd
//	                           --device /dev/dri/renderD128"); its read must
//	                           return the host's content.
//
// The agent joins no namespace, so the test needs no privilege beyond moving
// into the requester's cgroup.
func TestJoinRequesterCgroupGatesKfdRead(t *testing.T) {

	const node = "/sys/devices/virtual/kfd/kfd/topology/nodes/1/properties"

	denied := os.Getenv("SYSBOX_FS_TEST_DENIED_PID")
	granted := os.Getenv("SYSBOX_FS_TEST_GRANTED_PID")
	if denied == "" && granted == "" {
		t.Skip("set SYSBOX_FS_TEST_DENIED_PID and/or SYSBOX_FS_TEST_GRANTED_PID to run")
	}
	if _, err := os.Stat(node); err != nil {
		t.Skipf("no AMD KFD topology on this host: %v", err)
	}

	nss := []domain.NStype{}

	read := func(pidStr string) ([]byte, error) {
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			t.Fatalf("bad pid %q: %v", pidStr, err)
		}
		return agentRead(uint32(pid), true,
			&domain.ReadFilePayload{File: node, Len: 4096},
			nss)
	}

	if denied != "" {
		data, err := read(denied)
		ioerr, ok := err.(fuse.IOerror)
		if !ok || ioerr.Code != syscall.EPERM {
			t.Errorf("denied requester %s: read returned %d bytes, err=%v; want EPERM", denied, len(data), err)
		}
		// The errno must come from the kernel's read, not from a failed join
		// (join failures do not carry the kernel's message).
		if ok && !strings.Contains(ioerr.Message, "operation not permitted") {
			t.Errorf("denied requester %s: EPERM does not come from the kernel read: %q", denied, ioerr.Message)
		}

		// For the record: the same read without joining the requester's cgroup
		// runs under the test's own cgroup, which is what a plain passthrough
		// would do.
		pid, _ := strconv.Atoi(denied)
		plain, perr := agentRead(uint32(pid), false,
			&domain.ReadFilePayload{File: node, Len: 4096},
			nss)
		t.Logf("denied requester %s without join: %d bytes, err=%v", denied, len(plain), perr)
	}

	if granted != "" {
		want, err := os.ReadFile(node)
		if err != nil {
			t.Fatal(err)
		}
		got, err := read(granted)
		if err != nil {
			t.Fatalf("granted requester %s: %v", granted, err)
		}
		if string(got) != string(want) {
			t.Errorf("granted requester %s: got %d bytes, host has %d; content differs", granted, len(got), len(want))
		}
	}
}
