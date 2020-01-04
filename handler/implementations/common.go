//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

package implementations

import (
	"errors"
	"io"
	"os"
	"strings"
	"strconv"
	"syscall"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
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

func (h *CommonHandler) Lookup(n domain.IOnode, pid uint32) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method on %v handler", h.Name)

	// Identify the container holding the process represented by this pid. This
	// action can only succeed if the associated container has been previously
	// registered in sysbox-fs.
	css := h.Service.StateService()
	cntr := css.ContainerLookupByPid(pid)
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)", pid)
		return nil, errors.New("Container not found")
	}

	// Create nsenterEvent to initiate interaction with container namespaces.
	nss := h.Service.NSenterService()
	event := nss.NewEvent(
		cntr.InitPid(),
		[]domain.NStype{
			string(domain.NStypeUser),
			string(domain.NStypePid),
			string(domain.NStypeNet),
			string(domain.NStypeIpc),
			string(domain.NStypeCgroup),
			string(domain.NStypeUts),
		},
		&domain.NSenterMessage{Type: domain.LookupRequest, Payload: n.Path()},
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

func (h *CommonHandler) Getattr(n domain.IOnode, pid uint32) (*syscall.Stat_t, error) {

	logrus.Debugf("Executing Getattr() method on %v handler", h.Name)

	// Identify the container holding the process represented by this pid. This
	// action can only succeed if the associated container has been previously
	// registered in sysbox-fs.
	css := h.Service.StateService()
	cntr := css.ContainerLookupByPid(pid)
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)", pid)
		return nil, errors.New("Container not found")
	}

	stat := &syscall.Stat_t{
		Uid: cntr.UID(),
		Gid: cntr.GID(),
	}
	return stat, nil
}

func (h *CommonHandler) Open(n domain.IOnode, pid uint32) error {

	logrus.Debugf("Executing Open() method on %v handler", h.Name)

	// Identify the container holding the process represented by this pid. This
	// action can only succeed if the associated container has been previously
	// registered in sysbox-fs.
	css := h.Service.StateService()
	cntr := css.ContainerLookupByPid(pid)
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)", pid)
		return errors.New("Container not found")
	}

	// Create nsenterEvent to initiate interaction with container namespaces.
	nss := h.Service.NSenterService()
	event := nss.NewEvent(
		cntr.InitPid(),
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
				File: n.Path(),
				Flags: strconv.Itoa(n.OpenFlags()),
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

func (h *CommonHandler) Read(n domain.IOnode, pid uint32, buf []byte, off int64) (int, error) {

	logrus.Debugf("Executing Read() method on %v handler", h.Name)

	if off > 0 {
		return 0, io.EOF
	}

	name := n.Name()
	path := n.Path()

	// Identify the container holding the process represented by this pid. This
	// action can only succeed if the associated container has been previously
	// registered in sysbox-fs.
	css := h.Service.StateService()
	cntr := css.ContainerLookupByPid(pid)
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)", pid)
		return 0, errors.New("Container not found")
	}

	var (
		data string
		ok bool
		err error
	)

	if h.Cacheable {
		// Check if this resource has been initialized for this container. Otherwise,
		// fetch the information from the host FS and store it accordingly within
		// the container struct.
		data, ok = cntr.Data(path, name)
		if !ok {
			data, err = h.FetchFile(n, cntr)
			if err != nil {
				return 0, err
			}

			cntr.SetData(path, name, data)
		}
	} else {
		data, err = h.FetchFile(n, cntr)
		if err != nil {
			return 0, err
		}
	}

	data += "\n"

	return copyResultBuffer(buf, []byte(data))
}

func (h *CommonHandler) Write(n domain.IOnode, pid uint32, buf []byte) (int, error) {

	logrus.Debugf("Executing Write() method on %v handler", h.Name)

	name := n.Name()
	path := n.Path()

	newContent := strings.TrimSpace(string(buf))

	// Identify the container holding the process represented by this pid. This
	// action can only succeed if the associated container has been previously
	// registered in sysbox-fs.
	css := h.Service.StateService()
	cntr := css.ContainerLookupByPid(pid)
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)", pid)
		return 0, errors.New("Container not found")
	}

	if h.Cacheable {
		// Check if this resource has been initialized for this container. If not,
		// push it to the host FS and store it within the container struct.
		curContent, ok := cntr.Data(path, name)
		if !ok {
			if err := h.PushFile(n, cntr, newContent); err != nil {
				return 0, err
			}

			cntr.SetData(path, name, newContent)

			return len(buf), nil
		}

		// If new value matches the existing one, then there's noting else to be
		// done here.
		if newContent == curContent {
			return len(buf), nil
		}

		// Writing the new value into container-state struct.
		cntr.SetData(path, name, newContent)

	} else {
		// Push new value to host FS.
		if err := h.PushFile(n, cntr, newContent); err != nil {
			return 0, err
		}
	}

	return len(buf), nil
}

func (h *CommonHandler) ReadDirAll(n domain.IOnode, pid uint32) ([]os.FileInfo, error) {

	logrus.Debugf("Executing ReadDirAll() method on %v handler", h.Name)

	// Identify the container holding the process represented by this pid. This
	// action can only succeed if the associated container has been previously
	// registered in sysbox-fs.
	css := h.Service.StateService()
	cntr := css.ContainerLookupByPid(pid)
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)", pid)
		return nil, errors.New("Container not found")
	}

	// Create nsenterEvent to initiate interaction with container namespaces.
	nss := h.Service.NSenterService()
	event := nss.NewEvent(
		cntr.InitPid(),
		[]domain.NStype{
			string(domain.NStypeUser),
			string(domain.NStypePid),
			string(domain.NStypeNet),
			string(domain.NStypeIpc),
			string(domain.NStypeCgroup),
			string(domain.NStypeUts),
		},
		&domain.NSenterMessage{Type: domain.ReadDirRequest, Payload: n.Path()},
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
	osEmulatedFileEntries := h.EmulatedFilesInfo(n, pid)

	osFileEntries = append(osFileEntries, osEmulatedFileEntries...)

	return osFileEntries, nil
}

// Auxiliary routine to aid during ReadDirAll() execution.
func (h *CommonHandler) EmulatedFilesInfo(n domain.IOnode, pid uint32) []os.FileInfo {

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
		if handler.GetType() != domain.NODE_ADITION {
			continue
		}

		// Create temporary ionode to represent handler-path.
		ios := h.Service.IOService()
		newIOnode := ios.NewIOnode("", handlerPath, 0)

		// Handler execution.
		info, err := handler.Lookup(newIOnode, pid)
		if err != nil {
			logrus.Error("Lookup() error: ", err)
			return nil
		}

		emulatedFilesInfo = append(emulatedFilesInfo, info)
	}

	return emulatedFilesInfo
}

// Auxiliar method to fetch the content of any given file within a container.
func (h *CommonHandler) FetchFile(n domain.IOnode, c domain.ContainerIface) (string, error) {

	// Create nsenterEvent to initiate interaction with container namespaces.
	nss := h.Service.NSenterService()
	event := nss.NewEvent(
		c.InitPid(),
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

// Auxiliar method to inject content into any given file within a container.
func (h *CommonHandler) PushFile(n domain.IOnode, c domain.ContainerIface, s string) error {

	// Create nsenterEvent to initiate interaction with container namespaces.
	nss := h.Service.NSenterService()
	event := nss.NewEvent(
		c.InitPid(),
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
				File: n.Path(),
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
