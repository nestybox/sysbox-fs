//
// Copyright 2020 Nestybox, Inc.
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

// This file contains Sysbox's chown syscall trapping & handling code. The only
// reason we trap chown (as well as fchown and fchownat) is to prevent chown to
// /sys inside a sys container from failing. The reason chown to /sys inside a
// sys container would fail without this code is that /sys is owned by the
// host's true root, so it shows up as "nobody:nogroup" inside the sys container
// and thus its ownership can't be changed from within the container. Some apps
// running inside the container (e.g,. RedHat's RPM package manager) want to
// chown /sys to root:root, causing the apps to get an EPERM and fail.  As a
// work-around, Sysbox ignores chown to "/sys" inside the sys container (or in
// any inner containers). All other chown operations are handled normally by the
// kernel.

package seccomp

import (
	"path/filepath"
	"syscall"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

type chownSyscallInfo struct {
	syscallCtx // syscall generic info
	path       string
	pathFd     int32
	ownerUid   int64
	ownerGid   int64
	dirFd      int32
	dirPath    string
	flags      int
}

func (ci *chownSyscallInfo) ignoreChown(absPath string) bool {

	// Note: we only ignore chown targeting "/sys" directly. We purposely avoid
	// resolving symlinks to "/sys" because such symlinks are unusual and
	// resolving them would slow down every chown syscall. This means that if a
	// user chowns "/sys" by way of one or more symlinks, the syscall will not be
	// ignored and will thus still fail.

	if absPath != "/sys" {
		return false
	}

	// Check if /sys is a sysfs mount. In the rare case where it's not, we can't
	// ignore the chown.

	mts := ci.tracer.service.mts

	mip, err := mts.NewMountInfoParser(ci.cntr, ci.processInfo, true, false, false)
	if err != nil {
		logrus.Errorf("Failed to get mount info while processing fchown from pid %d: %s", ci.pid, err)
		return false
	}

	mi := mip.GetInfo(absPath)
	if mi == nil || mi.FsType != "sysfs" {
		return false
	}

	return true
}

func (ci *chownSyscallInfo) processChown() (*sysResponse, error) {
	var err error

	t := ci.tracer
	ci.processInfo = t.service.prs.ProcessCreate(ci.pid, 0, 0)

	ci.path, err = ci.processInfo.ResolveProcSelf(ci.path)
	if err != nil {
		return t.createErrorResponse(ci.reqId, syscall.EACCES), nil
	}

	if !filepath.IsAbs(ci.path) {
		ci.path = filepath.Join(ci.processInfo.Cwd(), ci.path)
	}

	if ci.ignoreChown(ci.path) {
		logrus.Debugf("Ignoring chown syscall from pid %d: path = %v, uid = %v, gid = %v",
			ci.pid, ci.path, ci.ownerUid, ci.ownerGid)
		return t.createSuccessResponse(ci.reqId), nil
	}

	return t.createContinueResponse(ci.reqId), nil
}

func (ci *chownSyscallInfo) processFchown() (*sysResponse, error) {

	t := ci.tracer
	ci.processInfo = t.service.prs.ProcessCreate(ci.pid, 0, 0)

	path, err := ci.processInfo.GetFd(ci.pathFd)
	if err != nil {
		return t.createContinueResponse(ci.reqId), nil
	}

	path, err = ci.processInfo.ResolveProcSelf(path)
	if err != nil {
		return t.createErrorResponse(ci.reqId, syscall.EACCES), nil
	}

	if !filepath.IsAbs(path) {
		path = filepath.Join(ci.processInfo.Cwd(), path)
	}

	if ci.ignoreChown(path) {
		logrus.Debugf("Ignoring chown syscall from pid %d: path = %v, uid = %v, gid = %v",
			ci.pid, path, ci.ownerUid, ci.ownerGid)
		return t.createSuccessResponse(ci.reqId), nil
	}

	return t.createContinueResponse(ci.reqId), nil
}

func (ci *chownSyscallInfo) processFchownat() (*sysResponse, error) {
	var err error

	t := ci.tracer
	ci.processInfo = t.service.prs.ProcessCreate(ci.pid, 0, 0)
	path := ci.path

	// Interpret dirFd (if the pathname is not absolute)
	if !filepath.IsAbs(path) {

		if (ci.flags&unix.AT_EMPTY_PATH == unix.AT_EMPTY_PATH) && path == "" {

			// Per chown(2): when the AT_EMPTY_PATH flag is set: If pathname is an
			// empty string, operate on the file referred to by dirfd. If dirfd is
			// AT_FDCWD, the call operates on the current working directory.

			if ci.dirFd == unix.AT_FDCWD {
				path = ci.processInfo.Cwd()
			} else {
				dirPath, err := ci.processInfo.GetFd(ci.dirFd)
				if err != nil {
					return t.createContinueResponse(ci.reqId), nil
				}
				path = dirPath
			}

		} else {

			// Per chown(2) (when the AT_EMPTY_PATH flag is not set):
			// dirFd is AT_FDCWD, path is interpreted relative to the process' current
			// working dir. Otherwise it's interpreted relative to dirFd.

			if ci.dirFd == unix.AT_FDCWD {
				path = filepath.Join(ci.processInfo.Cwd(), path)
			} else {
				dirPath, err := ci.processInfo.GetFd(ci.dirFd)
				if err != nil {
					return t.createContinueResponse(ci.reqId), nil
				}
				path = filepath.Join(dirPath, path)
			}
		}
	}

	path, err = ci.processInfo.ResolveProcSelf(path)
	if err != nil {
		return t.createErrorResponse(ci.reqId, syscall.EACCES), nil
	}

	if ci.ignoreChown(path) {
		logrus.Debugf("Ignoring fchownat syscall from pid %d: path = %v, uid = %v, gid = %v",
			ci.pid, path, ci.ownerUid, ci.ownerGid)
		return t.createSuccessResponse(ci.reqId), nil
	}

	return t.createContinueResponse(ci.reqId), nil
}

func (ci *chownSyscallInfo) processChownNSenter(nstype []domain.NStype) (*sysResponse, error) {

	chownPayload := []*domain.ChownSyscallPayload{}

	newElem := &domain.ChownSyscallPayload{
		Target:    ci.path,
		TargetUid: int(ci.ownerUid),
		TargetGid: int(ci.ownerGid),
	}

	chownPayload = append(chownPayload, newElem)

	nss := ci.tracer.service.nss
	event := nss.NewEvent(
		ci.pid,
		&nstype,
		&domain.NSenterMessage{
			Type:    domain.ChownSyscallRequest,
			Payload: chownPayload,
		},
		nil,
		false,
	)

	err := nss.SendRequestEvent(event)
	if err != nil {
		return nil, err
	}

	responseMsg := nss.ReceiveResponseEvent(event)
	if responseMsg.Type == domain.ErrorResponse {
		resp := ci.tracer.createErrorResponse(
			ci.reqId,
			responseMsg.Payload.(fuse.IOerror).Code)
		return resp, nil
	}

	return ci.tracer.createSuccessResponse(ci.reqId), nil
}
