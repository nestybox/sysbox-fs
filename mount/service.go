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
	hds domain.HandlerServiceIface        // for handlerDB interactions
	prs domain.ProcessServiceIface        // for process class interactions
}

func NewMountService() *MountService {
	return &MountService{}
}

func (mts *MountService) Setup(
	css domain.ContainerStateServiceIface,
	hds domain.HandlerServiceIface) {

	mts.css = css
	mts.hds = hds
}

func (mts *MountService) NewMountInfoParser(
	cntr domain.ContainerIface,
	pid uint32,
	deep bool) (domain.MountInfoParserIface, error) {

	if mts.mh == nil {
		mts.NewMountHelper()
	}

	return newMountInfoParser(cntr, pid, deep, mts)
}

func (mts *MountService) NewMountHelper() domain.MountHelperIface {

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
