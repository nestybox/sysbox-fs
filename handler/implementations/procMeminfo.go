// SPDX-License-Identifier: Apache-2.0

package implementations

import (
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
)

const cgroupMount = "/sys/fs/cgroup"

type ProcMeminfo struct {
	domain.HandlerBase
}

var ProcMeminfo_Handler = &ProcMeminfo{
	domain.HandlerBase{Name: "ProcMeminfo", Path: "/proc/meminfo", Enabled: true},
}

func (h *ProcMeminfo) Lookup(n domain.IOnodeIface, _ *domain.HandlerRequest) (os.FileInfo, error) {
	return &domain.FileInfo{Fname: n.Name(), Fmode: 0444}, nil
}

func (h *ProcMeminfo) Open(n domain.IOnodeIface, _ *domain.HandlerRequest) (bool, error) {
	if n.OpenFlags()&syscall.O_ACCMODE != syscall.O_RDONLY {
		return false, fuse.IOerror{Code: syscall.EACCES}
	}
	return false, nil
}

func (h *ProcMeminfo) Read(_ domain.IOnodeIface, req *domain.HandlerRequest) (int, error) {
	reader, err := unifiedCgroup(req.Pid)
	if err != nil {
		return 0, err
	}
	container, err := unifiedCgroup(req.Container.InitPid())
	if err != nil {
		return 0, err
	}
	// Sysbox starts its init process in a leaf under the container cgroup.
	container = strings.TrimSuffix(container, "/init.scope")
	if container == "" || container == "/" ||
		(reader != container && !strings.HasPrefix(reader, container+"/")) {
		return 0, fuse.IOerror{Code: syscall.EACCES}
	}

	limit, available, err := cgroupMemory(cgroupMount, reader, container)
	if err != nil {
		return 0, err
	}
	data := fmt.Sprintf("MemTotal: %d kB\nMemFree: %d kB\nMemAvailable: %d kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n",
		limit/1024, available/1024, available/1024)
	if req.Offset >= int64(len(data)) {
		return 0, io.EOF
	}
	return copy(req.Data, data[req.Offset:]), nil
}

func (h *ProcMeminfo) Write(domain.IOnodeIface, *domain.HandlerRequest) (int, error) {
	return 0, fuse.IOerror{Code: syscall.EACCES}
}

func (h *ProcMeminfo) ReadDirAll(domain.IOnodeIface, *domain.HandlerRequest) ([]os.FileInfo, error) {
	return nil, nil
}

func (h *ProcMeminfo) ReadLink(domain.IOnodeIface, *domain.HandlerRequest) (string, error) {
	return "", nil
}

func (h *ProcMeminfo) GetName() string                         { return h.Name }
func (h *ProcMeminfo) GetPath() string                         { return h.Path }
func (h *ProcMeminfo) GetEnabled() bool                        { return h.Enabled }
func (h *ProcMeminfo) SetEnabled(enabled bool)                 { h.Enabled = enabled }
func (h *ProcMeminfo) GetService() domain.HandlerServiceIface  { return h.Service }
func (h *ProcMeminfo) SetService(s domain.HandlerServiceIface) { h.Service = s }
func (h *ProcMeminfo) GetResourcesList() []string              { return nil }
func (h *ProcMeminfo) GetResourceMutex(domain.IOnodeIface) *sync.Mutex {
	return nil
}

func unifiedCgroup(pid uint32) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if path, ok := strings.CutPrefix(line, "0::"); ok && filepath.IsAbs(path) && filepath.Clean(path) == path {
			return path, nil
		}
	}
	return "", fuse.IOerror{Code: syscall.ENOTSUP}
}

func cgroupMemory(mount, reader, container string) (uint64, uint64, error) {
	const unlimited = uint64(math.MaxUint64)
	limit, available, sharedLimit := unlimited, unlimited, unlimited
	// Shared ancestors may cap the container but their usage includes other tasks.
	inside := true
	for path := reader; path != "/"; path = filepath.Dir(path) {
		dir := filepath.Join(mount, path)
		data, err := os.ReadFile(filepath.Join(dir, "memory.max"))
		if err != nil && !os.IsNotExist(err) {
			return 0, 0, err
		}
		if err == nil && strings.TrimSpace(string(data)) != "max" {
			max, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
			if err != nil {
				return 0, 0, err
			}
			limit = min(limit, max)
			if inside {
				headroom, err := memoryHeadroom(dir, max)
				if err != nil {
					return 0, 0, err
				}
				available = min(available, headroom)
			} else {
				sharedLimit = min(sharedLimit, max)
			}
		}
		inside = inside && path != container
	}
	if limit == unlimited {
		return 0, 0, fuse.IOerror{Code: syscall.ENODATA}
	}
	if sharedLimit != unlimited {
		// Charge the container's own usage against the shared cap.
		headroom, err := memoryHeadroom(filepath.Join(mount, container), sharedLimit)
		if err != nil {
			return 0, 0, err
		}
		available = min(available, headroom)
	}
	return limit, min(available, limit), nil
}

func memoryHeadroom(dir string, limit uint64) (uint64, error) {
	data, err := os.ReadFile(filepath.Join(dir, "memory.current"))
	if err != nil {
		return 0, err
	}
	used, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, err
	}
	return limit - min(used, limit), nil
}
