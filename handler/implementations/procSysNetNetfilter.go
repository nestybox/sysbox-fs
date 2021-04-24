//
// Copyright 2019-2020 Nestybox, Inc.
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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
)

//

type ProcSysNetNetfilter struct {
	domain.HandlerBase
}

var ProcSysNetNetfilter_Handler = &ProcSysNetNetfilter{
	domain.HandlerBase{
		Name: "ProcSysNetNetfilter",
		Path: "/proc/sys/net/netfilter",
		VcompsMap: map[string]domain.VcompsType{
			"nf_conntrack_max":                     domain.VcompFile,
			"nf_conntrack_tcp_timeout_established": domain.VcompFile,
			"nf_conntrack_tcp_timeout_close_wait":  domain.VcompFile,
		},
		Type:      domain.NODE_SUBSTITUTION,
		Enabled:   true,
		Cacheable: true,
	},
}

func (h *ProcSysNetNetfilter) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method for Req ID=%#x on %v handler",
		req.ID, h.Name)

	var lookupNode = filepath.Base(n.Path())

	// Return an artificial fileInfo if looked-up element matches any of the
	// virtual-components.
	if _, ok := h.VcompsMap[lookupNode]; ok {
		info := &domain.FileInfo{
			Fname:    lookupNode,
			Fmode:    os.FileMode(uint32(0644)),
			FmodTime: time.Now(),
		}

		return info, nil
	}

	// If looked-up element hasn't been found by now, let's look into the actual
	// sys container rootfs.
	procSysCommonHandler, ok := h.Service.FindHandler("/proc/sys/")
	if !ok {
		return nil, fmt.Errorf("No /proc/sys/ handler found")
	}
	if info, err := procSysCommonHandler.Lookup(n, req); err == nil {
		return info, nil
	}

	return nil, syscall.ENOENT
}

func (h *ProcSysNetNetfilter) Getattr(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (*syscall.Stat_t, error) {

	logrus.Debugf("Executing Getattr() method on %v handler", h.Name)

	return nil, nil
}

func (h *ProcSysNetNetfilter) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	logrus.Debugf("Executing %v Open() method\n", h.Name)

	return nil
}

func (h *ProcSysNetNetfilter) Close(n domain.IOnodeIface) error {

	logrus.Debugf("Executing Close() method on %v handler", h.Name)

	return nil
}

func (h *ProcSysNetNetfilter) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing %v Read() method", h.Name)

	// We are dealing with a single boolean element being read, so we can save
	// some cycles by returning right away if offset is any higher than zero.
	if req.Offset > 0 {
		return 0, io.EOF
	}

	name := n.Name()
	path := n.Path()
	cntr := req.Container

	// Ensure operation is generated from within a registered sys container.
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return 0, errors.New("Container not found")
	}

	var err error

	// Check if this resource has been initialized for this container. Otherwise,
	// fetch the information from the host FS and store it accordingly within
	// the container struct.
	cntr.Lock()
	data, ok := cntr.Data(path, name)
	if !ok {
		data, err = h.fetchFile(n, cntr)
		if err != nil && err != io.EOF {
			cntr.Unlock()
			return 0, err
		}

		cntr.SetData(path, name, data)
	}
	cntr.Unlock()

	data += "\n"

	return copyResultBuffer(req.Data, []byte(data))
}

func (h *ProcSysNetNetfilter) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing %v Write() method", h.Name)

	name := n.Name()
	path := n.Path()
	cntr := req.Container

	// Ensure operation is generated from within a registered sys container.
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return 0, errors.New("Container not found")
	}

	newVal := strings.TrimSpace(string(req.Data))
	newValInt, err := strconv.Atoi(newVal)
	if err != nil {
		logrus.Errorf("Unexpected error: %v", err)
		return 0, err
	}

	cntr.Lock()
	defer cntr.Unlock()

	if err := h.pushFile(n, cntr, newValInt); err != nil {
		return 0, err
	}
	cntr.SetData(path, name, newVal)
	return len(req.Data), nil
}

func (h *ProcSysNetNetfilter) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	logrus.Debugf("Executing ReadDirAll() method for Req ID=%#x on %v handler",
		req.ID, h.Name)

	// Ensure operation is generated from within a registered sys container.
	if req.Container == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return nil, errors.New("Container not found")
	}

	var (
		info        *domain.FileInfo
		fileEntries []os.FileInfo
	)

	// Obtain relative path to the element being read.
	relpath, err := filepath.Rel(h.Path, n.Path())
	if err != nil {
		return nil, err
	}

	// Iterate through map of virtual components.
	for k, _ := range h.VcompsMap {

		if relpath == filepath.Dir(k) {
			info = &domain.FileInfo{
				Fname:    filepath.Base(k),
				Fmode:    os.FileMode(uint32(0644)),
				FmodTime: time.Now(),
			}

			fileEntries = append(fileEntries, info)
		}
	}

	// Also collect procfs entries as seen within container's namespaces.
	procSysCommonHandler, ok := h.Service.FindHandler("/proc/sys/")
	if !ok {
		return nil, fmt.Errorf("No /proc/sys/ handler found")
	}
	commonNeigh, err := procSysCommonHandler.ReadDirAll(n, req)
	if err == nil {
		for _, entry := range commonNeigh {
			fileEntries = append(fileEntries, entry)
		}
	}

	return fileEntries, nil
}

func (h *ProcSysNetNetfilter) fetchFile(
	n domain.IOnodeIface,
	c domain.ContainerIface) (string, error) {

	// Read from kernel to extract the existing conntrack value.
	curHostVal, err := n.ReadLine()
	if err != nil && err != io.EOF {
		logrus.Errorf("Could not read from file %v", h.Path)
		return "", err
	}

	// High-level verification to ensure that format is the expected one.
	_, err = strconv.Atoi(curHostVal)
	if err != nil {
		logrus.Errorf("Unexpected content read from file %v, error %v", h.Path, err)
		return "", err
	}

	return curHostVal, nil
}

func (h *ProcSysNetNetfilter) pushFile(
	n domain.IOnodeIface,
	c domain.ContainerIface, newValInt int) error {

	// Push down to kernel the new value.
	msg := []byte(strconv.Itoa(newValInt))
	err := n.WriteFile(msg)
	if err != nil {
		logrus.Errorf("Could not write to file: %v", err)
		return err
	}

	return nil
}

func (h *ProcSysNetNetfilter) GetName() string {
	return h.Name
}

func (h *ProcSysNetNetfilter) GetPath() string {
	return h.Path
}

func (h *ProcSysNetNetfilter) GetEnabled() bool {
	return h.Enabled
}

func (h *ProcSysNetNetfilter) GetType() domain.HandlerType {
	return h.Type
}

func (h *ProcSysNetNetfilter) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *ProcSysNetNetfilter) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *ProcSysNetNetfilter) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
