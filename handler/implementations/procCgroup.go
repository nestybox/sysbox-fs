// SPDX-License-Identifier: Apache-2.0

package implementations

import (
	"io"
	"os"
	"sync"
	"syscall"

	"github.com/nestybox/sysbox-fs/cgroup"
	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
)

const cgroupMount = cgroup.Mount

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
	reader, container, err := cgroup.Scope(req.Pid, req.Container.InitPid())
	if err != nil {
		return 0, err
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
