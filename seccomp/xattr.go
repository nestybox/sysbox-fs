//
// Copyright 2021 Nestybox, Inc.
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

// This file contains Sysbox's *xattr syscall trapping & handling code. The
// reason we trap these syscalls is to allow processes inside the sys container
// that have sufficient capabilities (e.g., CAP_SYS_ADMIN) to set "trusted."
// extended attributes on files inside the container. The kernel does not
// currently allow this from within a user-namespace other than the initial user
// namespace (since it would allow an unprivileged user to unshare it's user-ns,
// become root in it, and set the trusted extended attribute on arbitrary
// files). But Sysbox allows this for processes inside the sys container because
// we know the container can only do this on files in its file-system jail.

package seccomp

import (
	"bytes"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
	cap "github.com/nestybox/sysbox-libs/capability"
	utils "github.com/nestybox/sysbox-libs/utils"

	"github.com/sirupsen/logrus"
)

var allowedXattrList = []string{
	"trusted.overlay.opaque",
}

type setxattrSyscallInfo struct {
	syscallCtx // syscall generic info
	pathFd     int32
	path       string
	name       string
	val        []byte
	flags      int
}

type getxattrSyscallInfo struct {
	syscallCtx // syscall generic info
	pathFd     int32
	path       string
	name       string
	addr       uint64
	size       uint64
}

type removexattrSyscallInfo struct {
	syscallCtx // syscall generic info
	pathFd     int32
	path       string
	name       string
}

type listxattrSyscallInfo struct {
	syscallCtx // syscall generic info
	pathFd     int32
	path       string
	addr       uint64
	size       uint64
}

// sanitizePath normalizes the file path associated with the xattr operation and
// ensures the process doing the syscall has access to it.
func sanitizePath(process domain.ProcessIface, path string) (string, error) {
	var err error

	// It's rare that the xattr be applied on a /proc/self/* path, but it's
	// technically possible.
	path, err = process.ResolveProcSelf(path)
	if err != nil {
		return path, syscall.EACCES
	}

	// Verify the process has the proper rights to access the file
	err = process.PathAccess(path, 0)
	if err != nil {
		return path, err
	}

	// Convert to absolute path if dealing with a relative path request.
	if !filepath.IsAbs(path) {
		path = filepath.Join(process.Cwd(), path)
	}

	// The process may be chroot'ed; adjust the path accordingly
	path = filepath.Join(process.Root(), path)

	return path, nil
}

func (si *setxattrSyscallInfo) processSetxattr() (*sysResponse, error) {
	var err error

	t := si.tracer

	if !utils.StringSliceContains(allowedXattrList, si.name) {
		return t.createContinueResponse(si.reqId), nil
	}

	// Ensure the process that performed the syscall has the required caps
	process := t.service.prs.ProcessCreate(si.pid, 0, 0)

	// We currently only handle trusted.* xattrs; these require CAP_SYS_ADMIN
	if !process.IsCapabilitySet(cap.EFFECTIVE, cap.CAP_SYS_ADMIN) {
		return t.createErrorResponse(si.reqId, syscall.EPERM), nil
	}

	// If pathFd is defined, we are processing fsetxattr(); convert pathFd to
	// path so we can then handle fsetxattr() as setxattr().
	if si.pathFd != 0 {
		si.path, err = process.GetFd(si.pathFd)
		if err != nil {
			return t.createContinueResponse(si.reqId), nil
		}
	}

	si.path, err = sanitizePath(process, si.path)
	if err != nil {
		return t.createErrorResponse(si.reqId, err), nil
	}

	logrus.Debugf("setxattr(): path = %s, name = %s, val = %s, flags = %x",
		si.path, si.name, string(si.val), si.flags)

	// Perform the nsenter into the process namespaces (except the user-ns)
	payload := domain.SetxattrSyscallPayload{
		Syscall: si.syscallName,
		Path:    si.path,
		Name:    si.name,
		Val:     si.val,
		Flags:   si.flags,
	}

	nss := t.service.nss
	event := nss.NewEvent(
		si.pid,
		&domain.AllNSsButUser,
		&domain.NSenterMessage{
			Type:    domain.SetxattrSyscallRequest,
			Payload: payload,
		},
		nil,
		false,
	)

	err = nss.SendRequestEvent(event)
	if err != nil {
		return nil, err
	}

	responseMsg := nss.ReceiveResponseEvent(event)
	if responseMsg.Type == domain.ErrorResponse {
		resp := t.createErrorResponse(
			si.reqId,
			responseMsg.Payload.(fuse.IOerror).Code)
		return resp, nil
	}

	return t.createSuccessResponse(si.reqId), nil
}

func (si *getxattrSyscallInfo) processGetxattr() (*sysResponse, error) {
	var err error

	t := si.tracer

	if !utils.StringSliceContains(allowedXattrList, si.name) {
		return t.createContinueResponse(si.reqId), nil
	}

	// Ensure process has required capabilities
	process := t.service.prs.ProcessCreate(si.pid, 0, 0)

	// We currently only handle trusted.* xattr; these require CAP_SYS_ADMIN
	if !process.IsCapabilitySet(cap.EFFECTIVE, cap.CAP_SYS_ADMIN) {
		return t.createErrorResponse(si.reqId, syscall.EPERM), nil
	}

	// If pathFd is defined, we are processing fgetxattr(); convert pathFd to
	// path so we can then handle fgetxattr() as getxattr().
	if si.pathFd != 0 {
		si.path, err = process.GetFd(si.pathFd)
		if err != nil {
			return t.createContinueResponse(si.reqId), nil
		}
	}

	si.path, err = sanitizePath(process, si.path)
	if err != nil {
		return t.createErrorResponse(si.reqId, err), nil
	}

	logrus.Debugf("getxattr(): path = %s, name = %s, size = %d",
		si.path, si.name, si.size)

	// Perform the nsenter into the process namespaces (except the user-ns)
	payload := domain.GetxattrSyscallPayload{
		Syscall: si.syscallName,
		Path:    si.path,
		Name:    si.name,
		Size:    si.size,
	}

	nss := t.service.nss
	event := nss.NewEvent(
		si.pid,
		&domain.AllNSsButUser,
		&domain.NSenterMessage{
			Type:    domain.GetxattrSyscallRequest,
			Payload: payload,
		},
		nil,
		false,
	)

	err = nss.SendRequestEvent(event)
	if err != nil {
		return nil, err
	}

	responseMsg := nss.ReceiveResponseEvent(event)

	if responseMsg.Type == domain.ErrorResponse {
		sysResp := t.createErrorResponse(
			si.reqId,
			responseMsg.Payload.(fuse.IOerror).Code)
		return sysResp, nil
	}

	resp := responseMsg.Payload.(domain.GetxattrRespPayload)

	// Write the data returned by getxattr() to the memory of the process whose
	// syscall we are processing.

	if si.size > 0 {
		if err := t.WriteRetVal(si.pid, si.addr, resp.Val); err != nil {
			sysResp := t.createErrorResponse(si.reqId, syscall.ENOTSUP)
			return sysResp, nil
		}
	}

	sysResp := t.createSuccessResponseWithRetValue(si.reqId, uint64(resp.Size))

	return sysResp, nil
}

func (si *removexattrSyscallInfo) processRemovexattr() (*sysResponse, error) {
	var err error

	t := si.tracer

	if !utils.StringSliceContains(allowedXattrList, si.name) {
		return t.createContinueResponse(si.reqId), nil
	}

	// Ensure process has required capabilities
	process := t.service.prs.ProcessCreate(si.pid, 0, 0)

	// We currently only handle trusted.* xattr; these require CAP_SYS_ADMIN
	if !process.IsCapabilitySet(cap.EFFECTIVE, cap.CAP_SYS_ADMIN) {
		return t.createErrorResponse(si.reqId, syscall.EPERM), nil
	}

	// If pathFd is defined, we are processing fremovexattr(); convert pathFd to
	// path so we can then handle fremovexattr() as removexattr().
	if si.pathFd != 0 {
		si.path, err = process.GetFd(si.pathFd)
		if err != nil {
			return t.createContinueResponse(si.reqId), nil
		}
	}

	si.path, err = sanitizePath(process, si.path)
	if err != nil {
		return t.createErrorResponse(si.reqId, err), nil
	}

	logrus.Debugf("removexattr(): path = %s, name = %s", si.path, si.name)

	// Perform the nsenter into the process namespaces (except the user-ns)
	payload := domain.RemovexattrSyscallPayload{
		Syscall: si.syscallName,
		Path:    si.path,
		Name:    si.name,
	}

	nss := t.service.nss
	event := nss.NewEvent(
		si.pid,
		&domain.AllNSsButUser,
		&domain.NSenterMessage{
			Type:    domain.RemovexattrSyscallRequest,
			Payload: payload,
		},
		nil,
		false,
	)

	err = nss.SendRequestEvent(event)
	if err != nil {
		return nil, err
	}

	responseMsg := nss.ReceiveResponseEvent(event)
	if responseMsg.Type == domain.ErrorResponse {
		resp := t.createErrorResponse(
			si.reqId,
			responseMsg.Payload.(fuse.IOerror).Code)
		return resp, nil
	}

	return t.createSuccessResponse(si.reqId), nil
}

func (si *listxattrSyscallInfo) processListxattr() (*sysResponse, error) {
	var err error

	t := si.tracer

	process := t.service.prs.ProcessCreate(si.pid, 0, 0)

	// If pathFd is defined, we are processing flistxattr(); convert pathFd to
	// path so we can then handle flistxattr() as listxattr().
	if si.pathFd != 0 {
		si.path, err = process.GetFd(si.pathFd)
		if err != nil {
			return t.createContinueResponse(si.reqId), nil
		}
	}

	si.path, err = sanitizePath(process, si.path)
	if err != nil {
		return t.createErrorResponse(si.reqId, err), nil
	}

	logrus.Debugf("listxattr(): path = %s, size = %d", si.path, si.size)

	// Perform the nsenter into the process namespaces (except the user-ns)
	payload := domain.ListxattrSyscallPayload{
		Syscall: si.syscallName,
		Path:    si.path,
		Size:    si.size,
	}

	nss := t.service.nss
	event := nss.NewEvent(
		si.pid,
		&domain.AllNSsButUser,
		&domain.NSenterMessage{
			Type:    domain.ListxattrSyscallRequest,
			Payload: payload,
		},
		nil,
		false,
	)

	err = nss.SendRequestEvent(event)
	if err != nil {
		return nil, err
	}

	responseMsg := nss.ReceiveResponseEvent(event)

	if responseMsg.Type == domain.ErrorResponse {
		sysResp := t.createErrorResponse(
			si.reqId,
			responseMsg.Payload.(fuse.IOerror).Code)
		return sysResp, nil
	}

	resp := responseMsg.Payload.(domain.ListxattrRespPayload)

	// Write the data returned by listxattr() to the memory of the process whose
	// syscall we are processing. But since sysbox-fs did listxattr() as root, we
	// must first filter out any xattr which the process performing the syscall
	// has no permissions to list.

	if si.size > 0 {

		// Filter out trusted.* if the process does not have CAP_SYS_ADMIN set.
		if !process.IsCapabilitySet(cap.EFFECTIVE, cap.CAP_SYS_ADMIN) {
			resp.Val = filterXattrList(resp.Val, "trusted.")
		}

		// Filter out security.capability.* if the process does not have CAP_SETFCAP set.
		if !process.IsCapabilitySet(cap.EFFECTIVE, cap.CAP_SETFCAP) {
			resp.Val = filterXattrList(resp.Val, "security.capability")
		}

		if err := t.WriteRetVal(si.pid, si.addr, resp.Val); err != nil {
			sysResp := t.createErrorResponse(si.reqId, syscall.ENOTSUP)
			return sysResp, nil
		}
	}

	sysResp := t.createSuccessResponseWithRetValue(si.reqId, uint64(resp.Size))

	return sysResp, nil
}

func filterXattrList(xattrList []byte, filterPrefix string) []byte {

	xattrs := bytes.Split(xattrList, []byte{'\x00'})
	filteredXattrs := []byte{}

	for _, attr := range xattrs {
		name := string(attr)
		if strings.HasPrefix(name, filterPrefix) {
			continue
		}
		attr = append(attr, byte('\x00'))
		filteredXattrs = append(filteredXattrs, attr...)
	}

	return filteredXattrs
}
