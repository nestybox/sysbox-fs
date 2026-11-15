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
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/nestybox/sysbox-fs/fuse"
	"github.com/nestybox/sysbox-runc/libcontainer/cgroups"
	"github.com/nestybox/sysbox-runc/libcontainer/cgroups/fs2"
)

//
// Device-cgroup joining for nsenter agents.
//
// Some kernel files that sysbox-fs passes through into a container are gated
// on the device cgroup of the task that reads them. The AMD KFD driver is the
// main case: GPU topology nodes under /sys/devices/virtual/kfd fail with EPERM
// unless the reader's device cgroup grants the GPU device nodes. The check is
// made against 'current' (the reading task), so an nsenter agent that only
// joins the container's namespaces is checked against sysbox-fs's own cgroup
// and would see the GPU regardless of what the container was granted.
//
// When NSenterEvent.JoinRequesterCgroup is set, sysbox-fs moves the agent into
// the device cgroup of the requesting process before the agent performs its
// request, so the kernel applies the device policy that governs that process,
// as it would for a read the process issued itself. This is deliberately the requester's cgroup,
// not the container init's: a process in an inner container (e.g., a docker
// container running inside a sys container) is then checked against its own,
// possibly narrower, device policy, as it would be under plain runc.
//
// Failure is fail-closed: if the device cgroup cannot be resolved, is frozen,
// or the agent cannot be moved into it, the request fails with EPERM and the
// read is never performed outside that cgroup.
//
// Notes:
//
// * Cgroup v2 forbids writing processes into a cgroup that has controllers
//   enabled for its children ("no internal processes"). The requester's own
//   cgroup always holds at least one process (the requester), so it never has
//   such controllers enabled, and the write is accepted.
//
// * The agent is short-lived and counts toward the cgroup's pids.max. If the
//   limit is reached, the write fails and the request is denied.
//
// * A frozen cgroup would stall the agent (and keep its nsenter read lock held,
//   which the zombie reaper waits on) until thaw. Frozen cgroups are rejected up front, and the response
//   wait is bounded by cgroupJoinResponseTimeout as a backstop for a freeze
//   that starts after the check.
//

// cgroupJoinResponseTimeout bounds how long sysbox-fs waits for an agent that
// joined a requester's device cgroup. The read itself takes microseconds; the
// bound only matters when the agent is stalled, e.g., by a freezer.
var cgroupJoinResponseTimeout = 5 * time.Second

// errCgroupFrozen is returned when the requester's device cgroup is frozen.
var errCgroupFrozen = errors.New("requester's device cgroup is frozen")

// mountFn returns the mountpoint of a cgroup hierarchy. The empty controller
// name denotes the cgroup v2 unified hierarchy.
type mountFn func(controller string) (string, error)

// defaultCgroupMount resolves real hierarchy mountpoints on the host.
func defaultCgroupMount(controller string) (string, error) {
	if controller == "" {
		return fs2.UnifiedMountpoint, nil
	}
	return cgroups.FindCgroupMountpoint("", controller)
}

// deviceCgroup is the cgroup whose device policy governs a requesting process.
type deviceCgroup struct {
	// dir is the cgroup directory: the unified (v2) cgroup, or the v1 devices
	// hierarchy cgroup. Processes are moved into it by writing cgroup.procs.
	dir string

	// freezerDir is the v1 freezer cgroup of the same process, or empty if the
	// freezer controller is absent. In v2, freeze state lives in dir.
	freezerDir string
}

// resolveDeviceCgroup returns the device cgroup named by the given
// /proc/<pid>/cgroup file. A v1 devices entry is authoritative when present
// (v1 and hybrid hosts enforce device policy there); otherwise the unified
// entry is used.
func resolveDeviceCgroup(procCgroupFile string, mount mountFn) (deviceCgroup, error) {

	entries, err := cgroups.ParseCgroupFile(procCgroupFile)
	if err != nil {
		return deviceCgroup{}, err
	}

	if p, ok := entries["devices"]; ok {
		m, err := mount("devices")
		if err != nil {
			return deviceCgroup{}, err
		}

		dc := deviceCgroup{dir: filepath.Join(m, p)}

		if fp, ok := entries["freezer"]; ok {
			if fm, err := mount("freezer"); err == nil {
				dc.freezerDir = filepath.Join(fm, fp)
			}
		}

		return dc, nil
	}

	if p, ok := entries[""]; ok {
		m, err := mount("")
		if err != nil {
			return deviceCgroup{}, err
		}

		return deviceCgroup{dir: filepath.Join(m, p)}, nil
	}

	return deviceCgroup{}, fmt.Errorf("no device cgroup listed in %s", procCgroupFile)
}

// frozen reports whether the device cgroup is frozen, or freezing. For v1 the
// freezer controller's state is checked; for v2 cgroup.freeze (requested) and
// cgroup.events (effective, which includes frozen ancestors) are checked.
func (dc deviceCgroup) frozen() (bool, error) {

	if dc.freezerDir != "" {
		b, err := os.ReadFile(filepath.Join(dc.freezerDir, "freezer.state"))
		if err != nil {
			return false, err
		}
		s := strings.TrimSpace(string(b))
		return s == "FROZEN" || s == "FREEZING", nil
	}

	// v2 path. A v1 devices cgroup without a freezer has neither file, and is
	// reported as not frozen; the response timeout still bounds the wait.
	if b, err := os.ReadFile(filepath.Join(dc.dir, "cgroup.freeze")); err == nil {
		if strings.TrimSpace(string(b)) == "1" {
			return true, nil
		}
	} else if !os.IsNotExist(err) {
		return false, err
	}

	b, err := os.ReadFile(filepath.Join(dc.dir, "cgroup.events"))
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == "frozen 1" {
			return true, nil
		}
	}

	return false, nil
}

// join moves the given process (and all its threads) into the device cgroup.
func (dc deviceCgroup) join(pid int) error {
	return cgroups.WriteCgroupProc(dc.dir, pid)
}

// requesterDeviceCgroup resolves the device cgroup of the process pid, as
// recorded in <procRoot>/<pid>/cgroup, and rejects frozen cgroups.
func requesterDeviceCgroup(pid uint32, procRoot string, mount mountFn) (deviceCgroup, error) {

	procCgroup := filepath.Join(procRoot, strconv.Itoa(int(pid)), "cgroup")

	dc, err := resolveDeviceCgroup(procCgroup, mount)
	if err != nil {
		return deviceCgroup{}, fmt.Errorf("resolving device cgroup of pid %d: %w", pid, err)
	}

	frozen, err := dc.frozen()
	if err != nil {
		return deviceCgroup{}, fmt.Errorf("checking freeze state of %s: %w", dc.dir, err)
	}

	if frozen {
		return deviceCgroup{}, fmt.Errorf("%w: %s", errCgroupFrozen, dc.dir)
	}

	return dc, nil
}

// cgroupJoinError converts a failure to join the requester's device cgroup
// into the errno reported to the requester. EPERM is used because the read is
// denied, not because the kernel denied it.
func cgroupJoinError(err error) error {
	return fuse.IOerror{
		RcvError: err,
		Type:     reflect.TypeOf(err).String(),
		Code:     syscall.EPERM,
		Message:  err.Error(),
	}
}

// setResponseTimeout bounds blocking reads on the nsenter socket.
func setResponseTimeout(fd int, timeout time.Duration) error {
	tv := syscall.NsecToTimeval(timeout.Nanoseconds())
	return syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
}
