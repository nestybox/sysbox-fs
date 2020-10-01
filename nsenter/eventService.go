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

package nsenter

import (
	"github.com/nestybox/sysbox-fs/domain"
)

type nsenterService struct {
	prs    domain.ProcessServiceIface // for process class interactions (capabilities)
	reaper *zombieReaper
}

func NewNSenterService() domain.NSenterServiceIface {
	return &nsenterService{
		reaper: newZombieReaper(),
	}
}

func (s *nsenterService) Setup(prs domain.ProcessServiceIface) {

	s.prs = prs
}

func (s *nsenterService) NewEvent(
	pid uint32,
	ns *[]domain.NStype,
	req *domain.NSenterMessage,
	res *domain.NSenterMessage) domain.NSenterEventIface {

	return &NSenterEvent{
		Pid:       pid,
		Namespace: ns,
		ReqMsg:    req,
		ResMsg:    res,
		reaper:    s.reaper,
	}
}

func (s *nsenterService) SendRequestEvent(e domain.NSenterEventIface) error {
	return e.SendRequest()
}

func (s *nsenterService) ReceiveResponseEvent(
	e domain.NSenterEventIface) *domain.NSenterMessage {

	return e.ReceiveResponse()
}

func (s *nsenterService) SetRequestEventPayload(
	e domain.NSenterEventIface,
	m *domain.NSenterMessage) {

	e.SetRequestMsg(m)
}

func (s *nsenterService) GetRequestEventPayload(
	e domain.NSenterEventIface) *domain.NSenterMessage {

	return e.GetRequestMsg()
}

func (s *nsenterService) SetResponseEventPayload(
	e domain.NSenterEventIface,
	m *domain.NSenterMessage) {

	e.SetResponseMsg(m)
}

func (s *nsenterService) GetResponseEventPayload(
	e domain.NSenterEventIface) *domain.NSenterMessage {

	return e.GetResponseMsg()
}
