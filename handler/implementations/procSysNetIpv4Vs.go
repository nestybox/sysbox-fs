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
// The procfs nodes managed in this handler will only be visible if the path
// they rely on (/proc/sys/net/ipv4/vs") is exposed within the system, which
// can only happen if the "ip_vs" kernel module is loaded.
//

//
// Note: this resource is already namespaced by the Linux kernel's net-ns. However the
// resource is hidden inside a non-init user-namespace. Thus, this handler's only purpose
// is to expose the resource inside a sys container. The same applies to all other resources
// under "/proc/sys/net/ipv4/vs/", though this handler only deals with "conntrack".
//
//
// /proc/sys/net/ipv4/vs/conn_reuse_mode handler
//
// Note: this resource is already namespaced by the Linux kernel's net-ns. However the
// resource is hidden inside a non-init user-namespace. Thus, this handler's only purpose
// is to expose the resource inside a sys container. The same applies to all other resources
// under "/proc/sys/net/ipv4/vs/", though this handler only deals with "conn_reuse_mode".
//
//
// /proc/sys/net/ipv4/vs/expire_nodest_conn handler
//
// Note: this resource is already namespaced by the Linux kernel's net-ns. However the
// resource is hidden inside a non-init user-namespace. Thus, this handler's only purpose
// is to expose the resource inside a sys container. The same applies to all other resources
// under "/proc/sys/net/ipv4/vs/", though this handler only deals with "expire_nodest_conn".
//
// /proc/sys/net/ipv4/vs/expire_quiescent_template handler
//
// Note: this resource is already namespaced by the Linux kernel's net-ns. However the
// resource is hidden inside a non-init user-namespace. Thus, this handler's only purpose
// is to expose the resource inside a sys container. The same applies to all other resources
// under "/proc/sys/net/ipv4/vs/", though this handler only deals with "expire_quiescent_template".
//

type ProcSysNetIpv4Vs struct {
	domain.HandlerBase
}

var ProcSysNetIpv4Vs_Handler = &ProcSysNetIpv4Vs{
	domain.HandlerBase{
		Name: "ProcSysNetIpv4Vs",
		Path: "/proc/sys/net/ipv4/vs",
		VcompsMap: map[string]domain.VcompsType{
			"conntrack":                 domain.VcompFile,
			"conn_reuse_mode":           domain.VcompFile,
			"expire_nodest_conn":        domain.VcompFile,
			"expire_quiescent_template": domain.VcompFile,
		},
		Type:      domain.NODE_SUBSTITUTION,
		Enabled:   true,
		Cacheable: true,
	},
}

func (h *ProcSysNetIpv4Vs) Lookup(
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

func (h *ProcSysNetIpv4Vs) Getattr(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (*syscall.Stat_t, error) {

	return nil, nil
}

func (h *ProcSysNetIpv4Vs) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) error {

	return nil
}

func (h *ProcSysNetIpv4Vs) Close(n domain.IOnodeIface) error {

	return nil
}

func (h *ProcSysNetIpv4Vs) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Read() method for Req ID=%#x on %v handler",
		req.ID, h.Name)

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

func (h *ProcSysNetIpv4Vs) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Write() method for Req ID=%#x on %v handler",
		req.ID, h.Name)

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

func (h *ProcSysNetIpv4Vs) ReadDirAll(
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

	// Iterate through map of virtual components.
	for k, _ := range h.VcompsMap {
		info = &domain.FileInfo{
			Fname:    k,
			FmodTime: time.Now(),
		}

		fileEntries = append(fileEntries, info)
	}

	return fileEntries, nil
}

func (h *ProcSysNetIpv4Vs) fetchFile(
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

func (h *ProcSysNetIpv4Vs) pushFile(
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

func (h *ProcSysNetIpv4Vs) GetName() string {
	return h.Name
}

func (h *ProcSysNetIpv4Vs) GetPath() string {
	return h.Path
}

func (h *ProcSysNetIpv4Vs) GetEnabled() bool {
	return h.Enabled
}

func (h *ProcSysNetIpv4Vs) GetType() domain.HandlerType {
	return h.Type
}

func (h *ProcSysNetIpv4Vs) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *ProcSysNetIpv4Vs) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *ProcSysNetIpv4Vs) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
