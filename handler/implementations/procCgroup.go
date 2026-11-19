// SPDX-License-Identifier: Apache-2.0

package implementations

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
)

const cgroupMount = "/sys/fs/cgroup"

type procCgroupFile struct {
	domain.HandlerBase
	render func(req *domain.HandlerRequest, reader, container string) (string, error)
}

func newProcCgroupFile(name, path string, render func(*domain.HandlerRequest, string, string) (string, error)) *procCgroupFile {
	return &procCgroupFile{
		HandlerBase: domain.HandlerBase{Name: name, Path: path, Enabled: true},
		render:      render,
	}
}

func (h *procCgroupFile) Lookup(n domain.IOnodeIface, _ *domain.HandlerRequest) (os.FileInfo, error) {
	return &domain.FileInfo{Fname: n.Name(), Fmode: 0444}, nil
}

func (h *procCgroupFile) Open(n domain.IOnodeIface, _ *domain.HandlerRequest) (bool, error) {
	if n.OpenFlags()&syscall.O_ACCMODE != syscall.O_RDONLY {
		return false, fuse.IOerror{Code: syscall.EACCES}
	}
	return false, nil
}

func (h *procCgroupFile) Read(_ domain.IOnodeIface, req *domain.HandlerRequest) (int, error) {
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

	data, err := h.render(req, reader, container)
	if err != nil {
		return 0, err
	}
	if req.Offset >= int64(len(data)) {
		return 0, io.EOF
	}
	return copy(req.Data, data[req.Offset:]), nil
}

func (h *procCgroupFile) Write(domain.IOnodeIface, *domain.HandlerRequest) (int, error) {
	return 0, fuse.IOerror{Code: syscall.EACCES}
}

func (h *procCgroupFile) ReadDirAll(domain.IOnodeIface, *domain.HandlerRequest) ([]os.FileInfo, error) {
	return nil, nil
}

func (h *procCgroupFile) ReadLink(domain.IOnodeIface, *domain.HandlerRequest) (string, error) {
	return "", nil
}

func (h *procCgroupFile) GetName() string                         { return h.Name }
func (h *procCgroupFile) GetPath() string                         { return h.Path }
func (h *procCgroupFile) GetEnabled() bool                        { return h.Enabled }
func (h *procCgroupFile) SetEnabled(enabled bool)                 { h.Enabled = enabled }
func (h *procCgroupFile) GetService() domain.HandlerServiceIface  { return h.Service }
func (h *procCgroupFile) SetService(s domain.HandlerServiceIface) { h.Service = s }
func (h *procCgroupFile) GetResourcesList() []string              { return nil }
func (h *procCgroupFile) GetResourceMutex(domain.IOnodeIface) *sync.Mutex {
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
