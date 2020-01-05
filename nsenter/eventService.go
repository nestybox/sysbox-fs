//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

package nsenter

import (
	"github.com/nestybox/sysbox-fs/domain"
)

type nsenterService struct {}

func NewNSenterService() domain.NSenterService {
	return &nsenterService{}
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