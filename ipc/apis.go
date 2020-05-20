//
// Copyright: (C) 2019-2020 Nestybox Inc.  All rights reserved.
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

	logrus.Infof("Container pre-registration message received for id: %s", data.Id)

	ipcService := ctx.(*ipcService)

	err := ipcService.css.ContainerPreRegister(data.Id)
	if err != nil {
		return err
	}

	logrus.Infof("Container pre-registration successfully completed for id: %s",
		data.Id)

	return nil
}

func ContainerRegister(ctx interface{}, data *grpc.ContainerData) error {

	logrus.Infof("Container registration message received for id: %s", data.Id)

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

	logrus.Infof("Container registration successfully completed for id: %s",
		data.Id)

	return nil
}

func ContainerUnregister(ctx interface{}, data *grpc.ContainerData) error {

	logrus.Infof("Container unregistration message received for id: %s", data.Id)

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

	logrus.Infof("Container unregistration successfully completed for id: %s",
		data.Id)

	return nil
}

func ContainerUpdate(ctx interface{}, data *grpc.ContainerData) error {

	logrus.Infof("Container update message received for id: %s", data.Id)

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

	logrus.Infof("Container update successfully processed for id: %s", data.Id)

	return nil
}
