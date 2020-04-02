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

	prs := h.Service.ProcessService()
	process := prs.ProcessCreate(req.Pid, req.Uid, req.Gid)

	// Identify the container holding the process represented by this pid. This
	// action can only succeed if the associated container has been previously
	// registered in sysbox-fs.
	css := h.Service.StateService()
	cntr := css.ContainerLookupByProcess(process)
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return nil, errors.New("Container not found")
	}

	// Create nsenterEvent to initiate interaction with container namespaces.
	nss := h.Service.NSenterService()
	event := nss.NewEvent(
		process.Pid(),
		[]domain.NStype{
			string(domain.NStypeUser),
			string(domain.NStypePid),
			string(domain.NStypeNet),
			string(domain.NStypeIpc),
			string(domain.NStypeCgroup),
			string(domain.NStypeUts),
		},
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

	prs := h.Service.ProcessService()
	process := prs.ProcessCreate(req.Pid, req.Uid, req.Gid)

	// Identify the container holding the process represented by this pid. This
	// action can only succeed if the associated container has been previously
	// registered in sysbox-fs.
	css := h.Service.StateService()
	cntr := css.ContainerLookupByProcess(process)
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return nil, errors.New("Container not found")
	}

	stat := &syscall.Stat_t{
		Uid: cntr.UID(),
		Gid: cntr.GID(),
	}

	return stat, nil
}

func (h *CommonHandler) Open(n domain.IOnode, req *domain.HandlerRequest) error {

	logrus.Debugf("Executing Open() method for Req ID=%#x on %v handler", req.ID, h.Name)

	prs := h.Service.ProcessService()
	process := prs.ProcessCreate(req.Pid, req.Uid, req.Gid)

	// Identify the container holding the process represented by this pid. This
	// action can only succeed if the associated container has been previously
	// registered in sysbox-fs.
	css := h.Service.StateService()
	cntr := css.ContainerLookupByProcess(process)
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)", req.Pid)
		return errors.New("Container not found")
	}

	// Create nsenterEvent to initiate interaction with container namespaces.
	nss := h.Service.NSenterService()
	event := nss.NewEvent(
		process.Pid(),
		[]domain.NStype{
			string(domain.NStypeUser),
			string(domain.NStypePid),
			string(domain.NStypeNet),
			string(domain.NStypeIpc),
			string(domain.NStypeCgroup),
			string(domain.NStypeUts),
		},
		&domain.NSenterMessage{
			Type: domain.OpenFileRequest,
			Payload: &domain.OpenFilePayload{
				Header: domain.NSenterMsgHeader{
					Pid:            process.Pid(),
					Uid:            process.Uid() - cntr.UID(),
					Gid:            process.Gid() - cntr.GID(),
					CapDacRead:     process.IsCapabilitySet(domain.EFFECTIVE, domain.CAP_DAC_READ_SEARCH),
					CapDacOverride: process.IsCapabilitySet(domain.EFFECTIVE, domain.CAP_DAC_OVERRIDE),
				},
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

	prs := h.Service.ProcessService()
	process := prs.ProcessCreate(req.Pid, req.Uid, req.Gid)

	// Identify the container holding the process represented by this pid. This
	// action can only succeed if the associated container has been previously
	// registered in sysbox-fs.
	css := h.Service.StateService()
	cntr := css.ContainerLookupByProcess(process)
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return 0, errors.New("Container not found")
	}

	var (
		data string
		ok   bool
		err  error
	)

	if h.Cacheable && domain.ProcessNsMatch(process, cntr.InitProc()) {
		// Check if this resource has been initialized for this container. Otherwise,
		// fetch the information from the host FS and store it accordingly within
		// the container struct.
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

	prs := h.Service.ProcessService()
	process := prs.ProcessCreate(req.Pid, req.Uid, req.Gid)

	newContent := strings.TrimSpace(string(req.Data))

	// Identify the container holding the process represented by this pid. This
	// action can only succeed if the associated container has been previously
	// registered in sysbox-fs.
	css := h.Service.StateService()
	cntr := css.ContainerLookupByProcess(process)
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return 0, errors.New("Container not found")
	}

	if h.Cacheable && domain.ProcessNsMatch(process, cntr.InitProc()) {
		// Push new value to host FS.
		if err := h.pushFile(n, process, newContent); err != nil {
			return 0, err
		}

		// Writing the new value into container-state struct.
		cntr.SetData(path, name, newContent)

	} else {
		// Push new value to host FS.
		if err := h.pushFile(n, process, newContent); err != nil {
			return 0, err
		}
	}

	return len(req.Data), nil
}

func (h *CommonHandler) ReadDirAll(n domain.IOnode, req *domain.HandlerRequest) ([]os.FileInfo, error) {

	logrus.Debugf("Executing ReadDirAll() method for Req ID=%#x on %v handler", req.ID, h.Name)

	prs := h.Service.ProcessService()
	process := prs.ProcessCreate(req.Pid, req.Uid, req.Gid)

	// Identify the container holding the process represented by this pid. This
	// action can only succeed if the associated container has been previously
	// registered in sysbox-fs.
	css := h.Service.StateService()
	cntr := css.ContainerLookupByProcess(process)
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return nil, errors.New("Container not found")
	}

	// Create nsenterEvent to initiate interaction with container namespaces.
	nss := h.Service.NSenterService()
	event := nss.NewEvent(
		process.Pid(),
		[]domain.NStype{
			string(domain.NStypeUser),
			string(domain.NStypePid),
			string(domain.NStypeNet),
			string(domain.NStypeIpc),
			string(domain.NStypeCgroup),
			string(domain.NStypeUts),
		},
		&domain.NSenterMessage{
			Type: domain.ReadDirRequest,
			Payload: &domain.ReadDirPayload{
				Header: domain.NSenterMsgHeader{
					Pid:            process.Pid(),
					Uid:            process.Uid() - cntr.UID(),
					Gid:            process.Gid() - cntr.GID(),
					CapDacRead:     process.IsCapabilitySet(domain.EFFECTIVE, domain.CAP_DAC_READ_SEARCH),
					CapDacOverride: process.IsCapabilitySet(domain.EFFECTIVE, domain.CAP_DAC_OVERRIDE),
				},
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

	// Transform event-response payload into a FileInfo slice. Notice that to
	// convert []T1 struct to a []T2 one, we must iterate through each element
	// and do the conversion one element at a time.
	dirEntries := responseMsg.Payload.([]domain.FileInfo)
	osFileEntries := make([]os.FileInfo, len(dirEntries))
	for i, v := range dirEntries {
		osFileEntries[i] = v
	}

	// Obtain FileEntries corresponding to emulated resources that could
	// potentially live in this folder.
	osEmulatedFileEntries := h.EmulatedFilesInfo(n, req)

	osFileEntries = append(osFileEntries, osEmulatedFileEntries...)

	return osFileEntries, nil
}

func (h *CommonHandler) Setattr(n domain.IOnode, req *domain.HandlerRequest) error {

	logrus.Debugf("Executing Setattr() method for Req ID=%#x on %v handler", req.ID, h.Name)

	prs := h.Service.ProcessService()
	process := prs.ProcessCreate(req.Pid, req.Uid, req.Gid)

	// Identify the container holding the process represented by this pid. This
	// action can only succeed if the associated container has been previously
	// registered in sysbox-fs.
	css := h.Service.StateService()
	cntr := css.ContainerLookupByProcess(process)
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return errors.New("Container not found")
	}

	// Create nsenterEvent to initiate interaction with container namespaces.
	nss := h.Service.NSenterService()
	event := nss.NewEvent(
		process.Pid(),
		[]domain.NStype{
			string(domain.NStypeUser),
			string(domain.NStypePid),
			string(domain.NStypeNet),
			string(domain.NStypeIpc),
			string(domain.NStypeCgroup),
			string(domain.NStypeUts),
		},
		&domain.NSenterMessage{
			Type: domain.OpenFileRequest,
			Payload: &domain.OpenFilePayload{
				Header: domain.NSenterMsgHeader{
					Pid:            process.Pid(),
					Uid:            process.Uid() - cntr.UID(),
					Gid:            process.Gid() - cntr.GID(),
					CapDacRead:     process.IsCapabilitySet(domain.EFFECTIVE, domain.CAP_DAC_READ_SEARCH),
					CapDacOverride: process.IsCapabilitySet(domain.EFFECTIVE, domain.CAP_DAC_OVERRIDE),
				},
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
func (h *CommonHandler) EmulatedFilesInfo(n domain.IOnode, req *domain.HandlerRequest) []os.FileInfo {

	var emulatedResources []string
	var emulatedFilesInfo []os.FileInfo

	// Obtain a list of all the emulated resources falling within the current
	// directory.
	emulatedResources = h.Service.DirHandlerEntries(n.Path())

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

		// Skip emulated resources that are mere 'substitutions' of an already
		// existing entry returned by the backend (container). A typical example
		// where this is seen: "/proc/sys/fs/binfmt_misc" folder. Notice that
		// this folder requires a handler to list nil file contents during
		// ReadDirAll() execution. As a consequence, this folder would be
		// displayed twice when executing ReadDirAll() for "/proc/sys/fs" folder:
		// 1) as a response of ReadDirAll() from container backend, and 2) as
		// execution of this function. Hence, to avoid double output, we are
		// only considering NODE_ADITION resources (i.e. resources not returned
		// by container) for further processing in this routine (e.g.
		// "/proc/sys/net/netfilter/nf_conntrack_max").
		if handler.GetType()&domain.NODE_ADITION != domain.NODE_ADITION {
			continue
		}

		// Create temporary ionode to represent handler-path.
		ios := h.Service.IOService()
		newIOnode := ios.NewIOnode("", handlerPath, 0)

		// Handler execution.
		info, err := handler.Lookup(newIOnode, req)
		if err != nil {
			logrus.Errorf("Lookup() error: %v", err)
			return nil
		}

		emulatedFilesInfo = append(emulatedFilesInfo, info)
	}

	return emulatedFilesInfo
}

// Auxiliary method to fetch the content of any given file within a container.
func (h *CommonHandler) fetchFile(
	n domain.IOnode,
	process domain.ProcessIface) (string, error) {

	// Create nsenterEvent to initiate interaction with container namespaces.
	nss := h.Service.NSenterService()
	event := nss.NewEvent(
		process.Pid(),
		[]domain.NStype{
			string(domain.NStypeUser),
			string(domain.NStypePid),
			string(domain.NStypeNet),
			string(domain.NStypeIpc),
			string(domain.NStypeCgroup),
			string(domain.NStypeUts),
		},
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
		[]domain.NStype{
			string(domain.NStypeUser),
			string(domain.NStypePid),
			string(domain.NStypeNet),
			string(domain.NStypeIpc),
			string(domain.NStypeCgroup),
			string(domain.NStypeUts),
		},
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
