//
// Copyright 2019-2026 Nestybox, Inc.
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

package process

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

const pidnsChildEnv = "SYSBOXFS_TEST_PIDNS_CHILD"

// The nsenter agent runs in the pid-ns of the process it serves, which may not
// match the procfs mounted at /proc (e.g., runc init before it mounts the
// container's procfs). Emulate that by running this test binary as pid 1 of a
// new pid-ns that keeps the parent's /proc.
func TestProcSelfPidInNewPidNs(t *testing.T) {
	if os.Getenv(pidnsChildEnv) == "1" {
		pidnsChild()
		return
	}

	if os.Geteuid() != 0 {
		t.Skip("creating a pid namespace requires root")
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestProcSelfPidInNewPidNs$")
	cmd.Env = append(os.Environ(), pidnsChildEnv+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWPID}

	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start child in new pid-ns: %v", err)
	}
	childPid := cmd.Process.Pid
	if err := cmd.Wait(); err != nil {
		t.Fatalf("child in new pid-ns failed: %v\n%s", err, out.String())
	}

	got := -1
	for _, line := range strings.Split(out.String(), "\n") {
		if v, ok := strings.CutPrefix(line, "procSelfPid="); ok {
			got, _ = strconv.Atoi(v)
		}
	}
	if got != childPid {
		t.Fatalf("ProcSelfPid() in new pid-ns = %d, want %d (pid seen by /proc)\n%s",
			got, childPid, out.String())
	}
}

func pidnsChild() {
	fail := func(format string, a ...interface{}) {
		fmt.Printf(format+"\n", a...)
		os.Exit(1)
	}

	if os.Getpid() != 1 {
		fail("expected to run as pid 1 of a new pid-ns, got pid %d", os.Getpid())
	}

	pid := ProcSelfPid()
	fmt.Printf("procSelfPid=%d\n", pid)

	p := NewProcessService().ProcessCreate(uint32(pid), 0, 0)

	if p.Uid() != uint32(os.Geteuid()) {
		fail("process uid = %d, want %d", p.Uid(), os.Geteuid())
	}

	// Same sequence the nsenter agent runs for overlayfs mounts.
	caps, err := p.GetEffCaps()
	if err != nil {
		fail("could not load the capabilities of this process: %v", err)
	}
	if caps == [2]uint32{0, 0} {
		fail("loaded an empty capability set")
	}
	if err := p.AdjustPersonality(p.Uid(), p.Gid(), p.Root(), p.Cwd(), caps); err != nil {
		fail("AdjustPersonality failed: %v", err)
	}

	os.Exit(0)
}
