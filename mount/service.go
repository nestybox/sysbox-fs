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

package mount

import (
	"strings"

	"github.com/nestybox/sysbox-fs/domain"
)

// List of sysbox-fs mountpoints within a sysbox container's procfs and sysfs.
//
// These mountpoints need to be tracked here to ensure that they are handled
// with special care. That is:
//
// * These mountpoints must be exposed in new procfs / sysfs file-systems
//   created within a sys container (e.g. chroot jails, l2 containers, etc).
//
// * During the sys container initialization process, sysbox-fs must avoid
//   generating a request to obtain the inodes associated to these mountpoints
//   -- see extractAllInodes(). The goal here is to prevent recursive i/o
//   operations from being able to arrive to sysbox-fs which could potentially
//   stall its FSM.

var ProcfsMounts = []string{
	"/proc/uptime",
	"/proc/swaps",
	"/proc/sys",
}

var SysfsMounts = []string{
	"/sys/kernel",
	"/sys/devices/virtual",
	"/sys/module/nf_conntrack/parameters",
}

// IsSysboxfsMount checks if the given path is at or under a sysbox-fs mount
func IsSysboxfsMount(path string) bool {

	// TODO: don't just check by path name; check that the given path is in fact
	// on a sysbox-fs managed mount. This likely requires dispatching an nsenter
	// agent to the container's mount ns to perform the check.

	for _, mountPath := range ProcfsMounts {
		if strings.HasPrefix(path, mountPath+"/") || path == mountPath {
			return true
		}
	}
	for _, mountPath := range SysfsMounts {
		if strings.HasPrefix(path, mountPath+"/") || path == mountPath {
			return true
		}
	}
	return false
}

type MountService struct {
	mh  *mountHelper                      // mountHelper instance for mount-clients
	css domain.ContainerStateServiceIface // for container-state interactions
	hds domain.HandlerServiceIface        // for handler package interactions
	prs domain.ProcessServiceIface        // for process package interactions
	nss domain.NSenterServiceIface        // for nsexec package interactions
}

func NewMountService() *MountService {
	return &MountService{}
}

func (mts *MountService) Setup(
	css domain.ContainerStateServiceIface,
	hds domain.HandlerServiceIface,
	prs domain.ProcessServiceIface,
	nss domain.NSenterServiceIface) {

	mts.css = css
	mts.hds = hds
	mts.prs = prs
	mts.nss = nss
}

func (mts *MountService) NewMountInfoParser(
	cntr domain.ContainerIface,
	process domain.ProcessIface,
	launchParser bool,
	fetchOptions bool,
	fetchInodes bool) (domain.MountInfoParserIface, error) {

	if mts.mh == nil {
		mts.NewMountHelper()
	}

	return newMountInfoParser(
		cntr,
		process,
		launchParser,
		fetchOptions,
		fetchInodes,
		mts,
	)
}

func (mts *MountService) NewMountHelper() domain.MountHelperIface {

	// Handler-service should be initialized by now, but there's one case
	// (nsexec's mts utilization) where a mount-service instance may be
	// partially initialized for reduced mts functionality.
	if mts.hds == nil {
		return nil
	}

	mts.mh = newMountHelper(mts)

	return mts.mh
}

func (mts *MountService) MountHelper() domain.MountHelperIface {
	return mts.mh
}
