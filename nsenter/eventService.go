//
// Copyright: (C) 2019-2020 Nestybox Inc.  All rights reserved.
//

package nsenter

import (
	"github.com/nestybox/sysbox-fs/domain"
)

type nsenterService struct {
	prs    domain.ProcessService // for process class interactions (capabilities)
	reaper *zombieReaper
}

func NewNSenterService(prs domain.ProcessService) domain.NSenterService {
	return &nsenterService{
		prs:    prs,
		reaper: newZombieReaper(),
	}
}

func (s *nsenterService) NewEvent(
	pid uint32,
	ns []domain.NStype,
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
