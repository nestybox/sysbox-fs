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

package ipc

import (
	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
	grpc "github.com/nestybox/sysbox-ipc/sysboxFsGrpc"
	grpcCodes "google.golang.org/grpc/codes"
	grpcStatus "google.golang.org/grpc/status"
)

type ipcService struct {
	grpcServer *grpc.Server
	css        domain.ContainerStateServiceIface
	prs        domain.ProcessServiceIface
	ios        domain.IOServiceIface
}

func NewIpcService() domain.IpcServiceIface {
	return &ipcService{}
}

func (ips *ipcService) Setup(
	css domain.ContainerStateServiceIface,
	prs domain.ProcessServiceIface,
	ios domain.IOServiceIface) {

	ips.css = css
	ips.prs = prs
	ips.ios = ios

	// Instantiate a grpcServer for inter-process communication.
	ips.grpcServer = grpc.NewServer(
		ips,
		&grpc.CallbacksMap{
			grpc.ContainerPreRegisterMessage: ContainerPreRegister,
			grpc.ContainerRegisterMessage:    ContainerRegister,
			grpc.ContainerUnregisterMessage:  ContainerUnregister,
			grpc.ContainerUpdateMessage:      ContainerUpdate,
		},
	)
}

func (ips *ipcService) Init() error {
	return ips.grpcServer.Init()
}

func ContainerPreRegister(ctx interface{}, data *grpc.ContainerData) error {

	logrus.Debugf("Container pre-registration started: id = %s", data.Id)

	ipcService := ctx.(*ipcService)

	err := ipcService.css.ContainerPreRegister(data.Id)
	if err != nil {
		return err
	}

	logrus.Debugf("Container pre-registration completed: id = %s", data.Id)

	return nil
}

func ContainerRegister(ctx interface{}, data *grpc.ContainerData) error {

	logrus.Debugf("Container registration started: id = %s", data.Id)

	ipcService := ctx.(*ipcService)

	// Create temporary container struct to be passed as reference to containerDB,
	// where the matching (real) container will be identified and then updated.
	cntr := ipcService.css.ContainerCreate(
		data.Id,
		uint32(data.InitPid),
		data.Ctime,
		uint32(data.UidFirst),
		uint32(data.UidSize),
		uint32(data.GidFirst),
		uint32(data.GidSize),
		data.ProcRoPaths,
		data.ProcMaskPaths,
	)

	err := ipcService.css.ContainerRegister(cntr)
	if err != nil {
		return err
	}

	logrus.Infof("Container registration completed: %v", cntr)

	return nil
}

func ContainerUnregister(ctx interface{}, data *grpc.ContainerData) error {

	logrus.Debugf("Container unregistration started: id = %s", data.Id)

	ipcService := ctx.(*ipcService)

	// Identify the container being unregistered.
	cntr := ipcService.css.ContainerLookupById(data.Id)
	if cntr == nil {
		return grpcStatus.Errorf(
			grpcCodes.NotFound,
			"Container %s not found",
			data.Id,
		)
	}

	err := ipcService.css.ContainerUnregister(cntr)
	if err != nil {
		return err
	}

	logrus.Infof("Container unregistration completed: id = %s", data.Id)

	return nil
}

func ContainerUpdate(ctx interface{}, data *grpc.ContainerData) error {

	logrus.Debugf("Container update started: id = %s", data.Id)

	ipcService := ctx.(*ipcService)

	// Create temporary container struct to be passed as reference to containerDB,
	// where the matching (real) container will be identified and then updated.
	cntr := ipcService.css.ContainerCreate(
		data.Id,
		uint32(data.InitPid),
		data.Ctime,
		uint32(data.UidFirst),
		uint32(data.UidSize),
		uint32(data.GidFirst),
		uint32(data.GidSize),
		data.ProcRoPaths,
		data.ProcMaskPaths,
	)

	err := ipcService.css.ContainerUpdate(cntr)
	if err != nil {
		return err
	}

	logrus.Debugf("Container update completed: id = %s", data.Id)

	return nil
}
