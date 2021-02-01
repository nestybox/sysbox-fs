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
	"github.com/nestybox/sysbox-fs/domain"
	"github.com/sirupsen/logrus"
)

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

	// Populate bind-mounts hashmap. Note that handlers are not operating at
	// this point, so there's no need to acquire locks for this operation.
	handlerDB := mts.hds.HandlerDB()
	if handlerDB == nil {
		logrus.Warnf("Seccomp-tracer initialization error: missing handlerDB")
		return nil
	}

	mts.mh = newMountHelper(handlerDB)

	return mts.mh
}

func (mts *MountService) MountHelper() domain.MountHelperIface {
	return mts.mh
}
