//
// Copyright: (C) 2019-2020 Nestybox Inc.  All rights reserved.
//

package implementations

import (
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/nestybox/sysbox-fs/domain"

	"github.com/sirupsen/logrus"
)

//
// Common Handler for all namespaced resources within /proc/sys subtree.
//
type CommonHandler struct {
	Name      string
	Path      string
	Type      domain.HandlerType
	Enabled   bool
	Cacheable bool
	Service   domain.HandlerService
}

func (h *CommonHandler) Lookup(n domain.IOnode, req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method for Req ID=%#x on %v handler", req.ID, h.Name)

	// Ensure operation is generated from within a registered sys container.
	if req.Container == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return nil, errors.New("Container not found")
	}

	// Create nsenterEvent to initiate interaction with container namespaces.
	nss := h.Service.NSenterService()
	event := nss.NewEvent(
		req.Pid,
		&domain.AllNSsButMount,
		&domain.NSenterMessage{
			Type: domain.LookupRequest,
			Payload: &domain.LookupPayload{
				Entry: n.Path(),
			},
		},
		nil,
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

	return info, nil
}

func (h *CommonHandler) Getattr(n domain.IOnode, req *domain.HandlerRequest) (*syscall.Stat_t, error) {

	logrus.Debugf("Executing Getattr() method for Req ID=%#x on %v handler", req.ID, h.Name)

	// Ensure operation is generated from within a registered sys container.
	if req.Container == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return nil, errors.New("Container not found")
	}

	stat := &syscall.Stat_t{
		Uid: req.Container.UID(),
		Gid: req.Container.GID(),
	}

	return stat, nil
}

func (h *CommonHandler) Open(n domain.IOnode, req *domain.HandlerRequest) error {

	logrus.Debugf("Executing Open() method for Req ID=%#x on %v handler", req.ID, h.Name)

	// Ensure operation is generated from within a registered sys container.
	if req.Container == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return errors.New("Container not found")
	}

	// Create nsenterEvent to initiate interaction with container namespaces.
	nss := h.Service.NSenterService()
	event := nss.NewEvent(
		req.Pid,
		&domain.AllNSsButMount,
		&domain.NSenterMessage{
			Type: domain.OpenFileRequest,
			Payload: &domain.OpenFilePayload{
				File:  n.Path(),
				Flags: strconv.Itoa(n.OpenFlags()),
				Mode:  strconv.Itoa(int(n.OpenMode())),
			},
		},
		nil,
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

func (h *CommonHandler) Close(node domain.IOnode) error {

	logrus.Debugf("Executing Close() method on %v handler", h.Name)

	return nil
}

func (h *CommonHandler) Read(n domain.IOnode, req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Read() method for Req ID=%#x on %v handler", req.ID, h.Name)

	if req.Offset > 0 {
		return 0, io.EOF
	}

	name := n.Name()
	path := n.Path()

	// Ensure operation is generated from within a registered sys container.
	if req.Container == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return 0, errors.New("Container not found")
	}

	var (
		data string
		ok   bool
		err  error
	)

	prs := h.Service.ProcessService()
	process := prs.ProcessCreate(req.Pid, req.Uid, req.Gid)
	cntr := req.Container

	//
	// Caching here improves performance by avoiding dispatching the nsenter agent.  But
	// note that caching is only helping processes at the sys container level, not in inner
	// containers or unshared namespaces. To enable caching for those, we would need to
	// have a cache per each namespace and this is expensive; plus we would also need to
	// know when the namespace ceases to exist in order to destroy the cache associated
	// with it.
	//
	if h.Cacheable && domain.ProcessNsMatch(process, cntr.InitProc()) {

		// If this resource is cached, return it's data; otherwise fetch its data from teh
		// host FS and store it in the cache.

		data, ok = cntr.Data(path, name)
		if !ok {
			data, err = h.fetchFile(n, process)
			if err != nil {
				return 0, err
			}

			cntr.SetData(path, name, data)
		}
	} else {
		data, err = h.fetchFile(n, process)
		if err != nil {
			return 0, err
		}
	}

	data += "\n"

	return copyResultBuffer(req.Data, []byte(data))
}

func (h *CommonHandler) Write(n domain.IOnode, req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Write() method for Req ID=%#x on %v handler", req.ID, h.Name)

	name := n.Name()
	path := n.Path()

	// Ensure operation is generated from within a registered sys container.
	if req.Container == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return 0, errors.New("Container not found")
	}

	newContent := strings.TrimSpace(string(req.Data))

	prs := h.Service.ProcessService()
	process := prs.ProcessCreate(req.Pid, req.Uid, req.Gid)
	cntr := req.Container

	// If caching is enabled, store the data in the cache and do a write-through to the
	// host FS. Otherwise just do the write-through.
	if h.Cacheable && domain.ProcessNsMatch(process, cntr.InitProc()) {
		if err := h.pushFile(n, process, newContent); err != nil {
			return 0, err
		}
		cntr.SetData(path, name, newContent)

	} else {
		if err := h.pushFile(n, process, newContent); err != nil {
			return 0, err
		}
	}

	return len(req.Data), nil
}

func (h *CommonHandler) ReadDirAll(n domain.IOnode, req *domain.HandlerRequest) ([]os.FileInfo, error) {

	logrus.Debugf("Executing ReadDirAll() method for Req ID=%#x on %v handler", req.ID, h.Name)

	// Ensure operation is generated from within a registered sys container.
	if req.Container == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return nil, errors.New("Container not found")
	}

	// Create nsenterEvent to initiate interaction with container namespaces.
	nss := h.Service.NSenterService()
	event := nss.NewEvent(
		req.Pid,
		&domain.AllNSsButMount,
		&domain.NSenterMessage{
			Type: domain.ReadDirRequest,
			Payload: &domain.ReadDirPayload{
				Dir: n.Path(),
			},
		},
		nil,
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

	// Obtain FileEntries corresponding to emulated resources that could
	// potentially live in this folder. These are resources that may not be
	// present in sys-container's fs, so we must take them into account to
	// return a complete ReadDirAll() response.
	osEmulatedFileEntries := h.EmulatedFilesInfo(n, req)
	if osEmulatedFileEntries != nil {
		for _, v := range *osEmulatedFileEntries {
			osFileEntries = append(osFileEntries, *v)
		}
	}

	// Transform event-response payload into a FileInfo slice. Notice that to
	// convert []T1 struct to a []T2 one, we must iterate through each element
	// and do the conversion one element at a time.
	dirEntries := responseMsg.Payload.([]domain.FileInfo)
	for _, v := range dirEntries {
		// Skip nodes that overlap with emulated resources already included in
		// the result buffer.
		if osEmulatedFileEntries != nil {
			if _, ok := (*osEmulatedFileEntries)[v.Name()]; ok {
				continue
			}
		}

		osFileEntries = append(osFileEntries, v)
	}

	return osFileEntries, nil
}

func (h *CommonHandler) Setattr(n domain.IOnode, req *domain.HandlerRequest) error {

	logrus.Debugf("Executing Setattr() method for Req ID=%#x on %v handler", req.ID, h.Name)

	// Ensure operation is generated from within a registered sys container.
	if req.Container == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return errors.New("Container not found")
	}

	// Create nsenterEvent to initiate interaction with container namespaces.
	nss := h.Service.NSenterService()
	event := nss.NewEvent(
		req.Pid,
		&domain.AllNSsButMount,
		&domain.NSenterMessage{
			Type: domain.OpenFileRequest,
			Payload: &domain.OpenFilePayload{
				File:  n.Path(),
				Flags: strconv.Itoa(n.OpenFlags()),
				Mode:  strconv.Itoa(int(n.OpenMode())),
			},
		},
		nil,
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

// Auxiliary routine to aid during ReadDirAll() execution.
func (h *CommonHandler) EmulatedFilesInfo(
	n domain.IOnode,
	req *domain.HandlerRequest) *map[string]*os.FileInfo {

	var emulatedResources []string

	// Obtain a list of all the emulated resources falling within the current
	// directory.
	emulatedResources = h.Service.DirHandlerEntries(n.Path())
	if len(emulatedResources) == 0 {
		return nil
	}

	var emulatedFilesInfo = make(map[string]*os.FileInfo)

	// For every emulated resource, invoke its Lookup() handler to obtain
	// the information required to satisfy this ongoing readDirAll()
	// instruction.
	for _, handlerPath := range emulatedResources {

		// Lookup the associated handler within handler-DB.
		handler, ok := h.Service.FindHandler(handlerPath)
		if !ok {
			logrus.Errorf("No supported handler for %v resource", handlerPath)
			return nil
		}

		// Create temporary ionode to represent handler-path.
		ios := h.Service.IOService()
		newIOnode := ios.NewIOnode("", handlerPath, 0)

		// Handler execution.
		info, err := handler.Lookup(newIOnode, req)
		if err != nil {
			return nil
		}

		emulatedFilesInfo[info.Name()] = &info
	}

	return &emulatedFilesInfo
}

// Auxiliary method to fetch the content of any given file within a container.
func (h *CommonHandler) fetchFile(
	n domain.IOnode,
	process domain.ProcessIface) (string, error) {

	// Create nsenterEvent to initiate interaction with container namespaces.
	nss := h.Service.NSenterService()
	event := nss.NewEvent(
		process.Pid(),
		&domain.AllNSsButMount,
		&domain.NSenterMessage{
			Type: domain.ReadFileRequest,
			Payload: &domain.ReadFilePayload{
				File: n.Path(),
			},
		},
		nil,
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

	info := responseMsg.Payload.(string)

	return info, nil
}

// Auxiliary method to inject content into any given file within a container.
func (h *CommonHandler) pushFile(
	n domain.IOnode,
	process domain.ProcessIface,
	s string) error {

	// Create nsenterEvent to initiate interaction with container namespaces.
	nss := h.Service.NSenterService()
	event := nss.NewEvent(
		process.Pid(),
		&domain.AllNSsButMount,
		&domain.NSenterMessage{
			Type: domain.WriteFileRequest,
			Payload: &domain.WriteFilePayload{
				File:    n.Path(),
				Content: s,
			},
		},
		nil,
	)

	// Launch nsenter-event to write file state within container
	// namespaces.
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

func (h *CommonHandler) GetName() string {
	return h.Name
}

func (h *CommonHandler) GetPath() string {
	return h.Path
}

func (h *CommonHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *CommonHandler) GetType() domain.HandlerType {
	return h.Type
}

func (h *CommonHandler) GetService() domain.HandlerService {
	return h.Service
}

func (h *CommonHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *CommonHandler) SetService(hs domain.HandlerService) {
	h.Service = hs
}
