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

package implementations

import (
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

//
// Pass-through handler
//
// Handler for all non-emulated resources under /proc/sys or /sys. It does a
// simple "passthrough" of the access by entering the namespaces of the
// container process that is doing the I/O operation and performs the access on
// behalf of it. It enters the namespaces by dispatching an "nsenter agent"
// process that enters the namespaces, performs the filesystem operation, and
// returns the result.  Note that the nsenter agent does NOT enter the mount
// namespace of the container process, to avoid a recursion of sysbox-fs mounts
// /proc/sys and /sys.
//

type PassThrough struct {
	domain.HandlerBase
}

var PassThrough_Handler = &PassThrough{
	domain.HandlerBase{
		Name:    "PassThrough",
		Path:    "*",
		Enabled: true,
	},
}

func (h *PassThrough) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	mountSysfs, mountProcfs, cloneFlags := checkProcAndSysRemount(n)

	// Create nsenterEvent to initiate interaction with container namespaces.
	nss := h.Service.NSenterService()
	event := nss.NewEvent(
		req.Pid,
		&domain.AllNSs,
		cloneFlags,
		&domain.NSenterMessage{
			Type: domain.LookupRequest,
			Payload: &domain.LookupPayload{
				Entry:       n.Path(),
				MountSysfs:  mountSysfs,
				MountProcfs: mountProcfs,
			},
		},
		nil,
		false,
	)

	// Launch nsenter-event.
	err := nss.SendRequestEvent(event)
	if err != nil {
		return nil, err
	}

	// Obtain nsenter-event response.
	responseMsg := nss.ReceiveResponseEvent(event)
	if responseMsg.Type == domain.ErrorResponse {
		return nil, responseMsg.Payload.(error)
	}

	info := responseMsg.Payload.(domain.FileInfo)

	// The file size will be 0 when passing through to files under /proc (i.e.,
	// because /proc is a virtual filesystem). This was not a problem in the
	// past, but starting with Linux kernel 6.5, returning a size of 0 causes the
	// kernel show the file as empty when read. Thus we need to return a size >
	// 0. However what size to we return? The size needs to be >= largest file
	// size that could be passed through, otherwise the contents of the file will
	// be cutoff. We choose size = 32K since it should be large enough to hold
	// the contents of any file under /proc. Note that files under /sys have a
	// size (typically 4096), so this override does not apply to them.
	if info.Fsize == 0 {
		info.Fsize = 32768
	}

	return info, nil
}

func (h *PassThrough) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (bool, error) {

	return h.OpenWithNS(n, req, domain.AllNSs)
}

func (h *PassThrough) OpenWithNS(
	n domain.IOnodeIface,
	req *domain.HandlerRequest,
	namespaces []domain.NStype) (bool, error) {

	logrus.Debugf("Executing Open() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	mountSysfs, mountProcfs, cloneFlags := checkProcAndSysRemount(n)

	// Create nsenterEvent to initiate interaction with container namespaces.
	nss := h.Service.NSenterService()
	event := nss.NewEvent(
		req.Pid,
		&namespaces,
		cloneFlags,
		&domain.NSenterMessage{
			Type: domain.OpenFileRequest,
			Payload: &domain.OpenFilePayload{
				File:        n.Path(),
				Flags:       strconv.Itoa(n.OpenFlags()),
				Mode:        strconv.Itoa(int(n.OpenMode())),
				MountSysfs:  mountSysfs,
				MountProcfs: mountProcfs,
			},
		},
		nil,
		false,
	)

	// Launch nsenter-event.
	err := nss.SendRequestEvent(event)
	if err != nil {
		return false, err
	}

	// Obtain nsenter-event response.
	responseMsg := nss.ReceiveResponseEvent(event)
	if responseMsg.Type == domain.ErrorResponse {
		return false, responseMsg.Payload.(error)
	}

	return false, nil
}

// Reads the given node by entering all container namespaces.
// Caches the result after reading, to avoid the performance hit of entering the
// container namespaces in future calls (unless req.noCache is set).
func (h *PassThrough) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	return h.ReadWithNS(n, req, domain.AllNSs)
}

// Same as Read(), but enters the given container namespaces only.
func (h *PassThrough) ReadWithNS(
	n domain.IOnodeIface,
	req *domain.HandlerRequest,
	namespaces []domain.NStype) (int, error) {

	var (
		sz  int
		err error
	)

	logrus.Debugf("Executing Read() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	path := n.Path()
	cntr := req.Container

	prs := h.Service.ProcessService()
	process := prs.ProcessCreate(req.Pid, req.Uid, req.Gid)

	// The passthrough driver is slow because it must spawn a process that enters
	// the container's namespaces (i.e., the nsenter agent) and read the data
	// from there. To improve things, we cache the data on the first access to
	// avoid dispatching the nsenter agent on subsequent accesses.
	//
	// A couple of caveats on the caching:
	//
	// 1) Caching is only done for processes at the sys container level, not in
	// inner containers or inner unshared namespaces. To enable caching for
	// those, we would need to have a cache per each namespace set (since the
	// values under /proc/sys depend on the namespaces that the process belongs
	// to). This would be expensive and would also require Sysbox to know when
	// the namespace ceases to exist in order to destroy the cache associated
	// with it.
	//
	// 2) As an optimization, we fetch data from the container's filesystem only
	// when the req.Offset is 0. For req.Offset > 0, we assume that the data is
	// cached already. Without this optimization, we will likely go through
	// fetchFile() twice for each read: one with req.Offset 0, and one at
	// req.Offset X, where X is the number of bytes of the resource being
	// read. That is, the handler's Read() method is normally invoked twice: the
	// first read returns X bytes, the second read returns 0 bytes.

	if domain.ProcessNsMatch(process, cntr.InitProc()) {

		cntr.Lock()

		// Check the data cache
		sz, err = cntr.Data(path, req.Offset, &req.Data)
		if err != nil && err != io.EOF {
			cntr.Unlock()
			return 0, fuse.IOerror{Code: syscall.EINVAL}
		}

		if req.Offset == 0 && sz == 0 && err == io.EOF {

			// Resource is not cached, read it from the filesystem.
			sz, err = h.fetchFile(process, namespaces, n, req.Offset, &req.Data)
			if err != nil {
				cntr.Unlock()
				return 0, fuse.IOerror{Code: syscall.EINVAL}
			}

			if sz == 0 {
				cntr.Unlock()
				return 0, nil
			}

			if !req.NoCache {
				err = cntr.SetData(path, req.Offset, req.Data)
				if err != nil {
					cntr.Unlock()
					return 0, fuse.IOerror{Code: syscall.EINVAL}
				}
			}
		}

		cntr.Unlock()

	} else {
		sz, err = h.fetchFile(process, namespaces, n, req.Offset, &req.Data)
		if err != nil {
			return 0, fuse.IOerror{Code: syscall.EINVAL}
		}
	}

	return sz, nil
}

// Writes to the given node by entering all the container namespaces.
// Caches the result after writing, to avoid the performance hit of entering the
// container namespaces in future read calls (unless req.noCache is set).
func (h *PassThrough) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	return h.WriteWithNS(n, req, domain.AllNSs)
}

// Same as Write(), but enters the given container namespaces only.
func (h *PassThrough) WriteWithNS(
	n domain.IOnodeIface,
	req *domain.HandlerRequest,
	namespaces []domain.NStype) (int, error) {

	var (
		len int
		err error
	)

	resource := n.Name()

	logrus.Debugf("Executing Write() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	path := n.Path()
	cntr := req.Container

	prs := h.Service.ProcessService()
	process := prs.ProcessCreate(req.Pid, req.Uid, req.Gid)

	if len, err = h.pushFile(process, namespaces, n, req.Offset, req.Data); err != nil {
		return 0, err
	}

	// If the write comes from a process inside the sys container's namespaces,
	// (not in inner containers or unshared namespaces) then cache the data.
	// See explanation in Read() method above.

	if domain.ProcessNsMatch(process, cntr.InitProc()) {
		if !req.NoCache {
			cntr.Lock()
			err = cntr.SetData(path, req.Offset, req.Data)
			if err != nil {
				cntr.Unlock()
				return 0, fuse.IOerror{Code: syscall.EINVAL}
			}
			cntr.Unlock()
		}
	}

	return len, nil
}

func (h *PassThrough) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	logrus.Debugf("Executing ReadDirAll() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	mountSysfs, mountProcfs, cloneFlags := checkProcAndSysRemount(n)

	// Create nsenterEvent to initiate interaction with container namespaces.
	nss := h.Service.NSenterService()
	event := nss.NewEvent(
		req.Pid,
		&domain.AllNSs,
		cloneFlags,
		&domain.NSenterMessage{
			Type: domain.ReadDirRequest,
			Payload: &domain.ReadDirPayload{
				Dir:         n.Path(),
				MountSysfs:  mountSysfs,
				MountProcfs: mountProcfs,
			},
		},
		nil,
		false,
	)

	// Launch nsenter-event.
	err := nss.SendRequestEvent(event)
	if err != nil {
		return nil, err
	}

	// Obtain nsenter-event response.
	responseMsg := nss.ReceiveResponseEvent(event)
	if responseMsg.Type == domain.ErrorResponse {
		return nil, responseMsg.Payload.(error)
	}

	var osFileEntries = make([]os.FileInfo, 0)

	// Transform event-response payload into a FileInfo slice. Notice that to
	// convert []T1 struct to a []T2 one, we must iterate through each element
	// and do the conversion one element at a time.
	dirEntries := responseMsg.Payload.([]domain.FileInfo)
	for _, v := range dirEntries {
		osFileEntries = append(osFileEntries, v)
	}

	return osFileEntries, nil
}

func (h *PassThrough) ReadLink(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (string, error) {

	logrus.Debugf("Executing ReadLink() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	mountSysfs, mountProcfs, cloneFlags := checkProcAndSysRemount(n)

	// Create nsenterEvent to initiate interaction with container namespaces.
	nss := h.Service.NSenterService()

	event := nss.NewEvent(
		req.Pid,
		&domain.AllNSs,
		cloneFlags,
		&domain.NSenterMessage{
			Type: domain.ReadLinkRequest,
			Payload: &domain.ReadLinkPayload{
				Link:        n.Path(),
				MountSysfs:  mountSysfs,
				MountProcfs: mountProcfs,
			},
		},
		nil,
		false,
	)

	// Launch nsenter-event to obtain file state within container
	// namespaces.
	err := nss.SendRequestEvent(event)
	if err != nil {
		return "", err
	}

	// Obtain nsenter-event response.
	responseMsg := nss.ReceiveResponseEvent(event)
	if responseMsg.Type == domain.ErrorResponse {
		return "", responseMsg.Payload.(error)
	}

	resp := responseMsg.Payload.(string)

	return resp, nil
}

func (h *PassThrough) Setattr(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	logrus.Debugf("Executing Setattr() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	mountSysfs, mountProcfs, cloneFlags := checkProcAndSysRemount(n)

	// Create nsenterEvent to initiate interaction with container namespaces.
	nss := h.Service.NSenterService()
	event := nss.NewEvent(
		req.Pid,
		&domain.AllNSs,
		cloneFlags,
		&domain.NSenterMessage{
			Type: domain.OpenFileRequest,
			Payload: &domain.OpenFilePayload{
				File:        n.Path(),
				Flags:       strconv.Itoa(n.OpenFlags()),
				Mode:        strconv.Itoa(int(n.OpenMode())),
				MountSysfs:  mountSysfs,
				MountProcfs: mountProcfs,
			},
		},
		nil,
		false,
	)

	// Launch nsenter-event.
	err := nss.SendRequestEvent(event)
	if err != nil {
		return err
	}

	// Obtain nsenter-event response.
	responseMsg := nss.ReceiveResponseEvent(event)
	if responseMsg.Type == domain.ErrorResponse {
		return responseMsg.Payload.(error)
	}

	return nil
}

// Auxiliary method to fetch the content of any given file within a container.
func (h *PassThrough) fetchFile(
	process domain.ProcessIface,
	namespaces []domain.NStype,
	n domain.IOnodeIface,
	offset int64,
	data *[]byte) (int, error) {

	mountSysfs, mountProcfs, cloneFlags := checkProcAndSysRemount(n)

	// Create nsenterEvent to initiate interaction with container namespaces.
	nss := h.Service.NSenterService()

	event := nss.NewEvent(
		process.Pid(),
		&namespaces,
		cloneFlags,
		&domain.NSenterMessage{
			Type: domain.ReadFileRequest,
			Payload: &domain.ReadFilePayload{
				File:        n.Path(),
				Offset:      offset,
				Len:         len(*data),
				MountSysfs:  mountSysfs,
				MountProcfs: mountProcfs,
			},
		},
		nil,
		false,
	)

	// Launch nsenter-event to obtain file state within container
	// namespaces.
	err := nss.SendRequestEvent(event)
	if err != nil {
		return 0, err
	}

	// Obtain nsenter-event response.
	responseMsg := nss.ReceiveResponseEvent(event)
	if responseMsg.Type == domain.ErrorResponse {
		return 0, responseMsg.Payload.(error)
	}

	*data = responseMsg.Payload.([]byte)

	return len(*data), nil
}

// Auxiliary method to inject content into any given file within a container.
func (h *PassThrough) pushFile(
	process domain.ProcessIface,
	namespaces []domain.NStype,
	n domain.IOnodeIface,
	offset int64,
	data []byte) (int, error) {

	mountSysfs, mountProcfs, cloneFlags := checkProcAndSysRemount(n)

	// Create nsenterEvent to initiate interaction with container namespaces.
	nss := h.Service.NSenterService()

	event := nss.NewEvent(
		process.Pid(),
		&namespaces,
		cloneFlags,
		&domain.NSenterMessage{
			Type: domain.WriteFileRequest,
			Payload: &domain.WriteFilePayload{
				File:        n.Path(),
				Offset:      offset,
				Data:        data,
				MountSysfs:  mountSysfs,
				MountProcfs: mountProcfs,
			},
		},
		nil,
		false,
	)

	// Launch nsenter-event to write file state within container
	// namespaces.
	err := nss.SendRequestEvent(event)
	if err != nil {
		return 0, err
	}

	// Obtain nsenter-event response.
	responseMsg := nss.ReceiveResponseEvent(event)
	if responseMsg.Type == domain.ErrorResponse {
		return 0, responseMsg.Payload.(error)
	}

	return len(data), nil
}

func (h *PassThrough) GetName() string {
	return h.Name
}

func (h *PassThrough) GetPath() string {
	return h.Path
}

func (h *PassThrough) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *PassThrough) GetEnabled() bool {
	return h.Enabled
}

func (h *PassThrough) SetEnabled(b bool) {
	h.Enabled = b
}

func (h *PassThrough) GetResourcesList() []string {

	var resources []string

	for resourceKey, resource := range h.EmuResourceMap {
		resource.Mutex.Lock()
		if !resource.Enabled {
			resource.Mutex.Unlock()
			continue
		}
		resource.Mutex.Unlock()

		resources = append(resources, filepath.Join(h.GetPath(), resourceKey))
	}

	return resources
}

func (h *PassThrough) GetResourceMutex(n domain.IOnodeIface) *sync.Mutex {
	resource, ok := h.EmuResourceMap[n.Name()]
	if !ok {
		return nil
	}

	return &resource.Mutex
}

func (h *PassThrough) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}

// checkProcAndSysRemount checks if the nsenter agent deployed by the passthrough handler
// should remount procfs and sysfs.
func checkProcAndSysRemount(n domain.IOnodeIface) (bool, bool, uint32) {
	var (
		mountSysfs  bool
		mountProcfs bool
		cloneFlags  uint32
	)

	// The nsenter agent will enter/join the namespaces of the container,
	// including the mount ns. This way, the nsenter process no longer carries
	// the sysbox-fs mounts as it enters the container.
	//
	// However, when accessing files under /proc or /sys, the agent needs to
	// remount these as otherwise they won't pick up the container's assigned
	// resources (e.g., net devices, etc).
	//
	// To avoid the container processes seeing the nsenter process mounts of
	// procfs and sysfs, we direct the nsenter agent create a new mount namespace
	// so as to not mess up mounts in the container (see cloneFlags below). The
	// creation of this new mount ns occurs **after** the nsenter process has
	// joined the container namespaces (see sysbox-runc/libcontainer/nsexec). Thus it's
	// equivalent to a "setns" to join all container namespaces, immediately
	// followed by an "unshare" of the mount namespace.

	if strings.HasPrefix(n.Path(), "/sys/") {
		mountSysfs = true
	}

	if strings.HasPrefix(n.Path(), "/proc/") {
		mountProcfs = true
	}

	// Tell nsenter agent to unshare the mount-ns (occurs after nsenter has
	// already joined container namespaces).
	if mountSysfs || mountProcfs {
		cloneFlags = unix.CLONE_NEWNS
	}

	return mountSysfs, mountProcfs, cloneFlags
}
