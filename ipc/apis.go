//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

package ipc

import (
	"errors"
	"strconv"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
	grpc "github.com/nestybox/sysbox-ipc/sysboxFsGrpc"
)

type ipcService struct {
	grpcServer *grpc.Server
	css        domain.ContainerStateService
	ios        domain.IOService
}

func NewIpcService(
	css domain.ContainerStateService,
	ios domain.IOService) domain.IpcService {

	// Instantiate a grpcServer for inter-process communication.
	newService := new(ipcService)
	newService.css = css
	newService.ios = ios
	newService.grpcServer = grpc.NewServer(
		newService,
		&grpc.CallbacksMap{
			grpc.ContainerRegisterMessage:   ContainerRegister,
			grpc.ContainerUnregisterMessage: ContainerUnregister,
			grpc.ContainerUpdateMessage:     ContainerUpdate,
		},
	)
	if newService == nil {
		return nil
	}

	return newService
}

func (s *ipcService) Init() {
	go s.grpcServer.Init()
}

func ContainerRegister(ctx interface{}, data *grpc.ContainerData) error {

	if data == nil {
		return errors.New("Invalid input parameters")
	}

	logrus.Info("Container registration message received for initPid: ", data.InitPid)

	ipcService := ctx.(*ipcService)

	// Identify the pidNsInode corresponding to this pid.
	tmpNode := ipcService.ios.NewIOnode("", strconv.Itoa(int(data.InitPid)), 0)
	pidInode, err := ipcService.ios.PidNsInode(tmpNode)
	if err != nil {
		return err
	}

	// Create new container and add it to the containerDB.
	cntr := ipcService.css.ContainerCreate(
		data.Id,
		uint32(data.InitPid),
		pidInode,
		data.Ctime,
		uint32(data.UidFirst),
		uint32(data.UidSize),
		uint32(data.GidFirst),
		uint32(data.GidSize),
	)

	err = ipcService.css.ContainerAdd(cntr)
	if err != nil {
		return err
	}

	logrus.Info("Container registration successfully completed")

	return nil
}

func ContainerUnregister(ctx interface{}, data *grpc.ContainerData) error {

	if data == nil {
		return errors.New("Invalid input parameters")
	}

	logrus.Info("Container unregistration message received...")

	ipcService := ctx.(*ipcService)

	// Create temporary container struct to be passed as reference to containerDB,
	// where the matching (real) container will be identified and then eliminated.
	cntr := ipcService.css.ContainerCreate(
		data.Id,
		uint32(data.InitPid),
		0,
		data.Ctime,
		uint32(data.UidFirst),
		uint32(data.UidSize),
		uint32(data.GidFirst),
		uint32(data.GidSize),
	)

	err := ipcService.css.ContainerDelete(cntr)
	if err != nil {
		return err
	}

	logrus.Info("Container unregistration successfully completed")

	return nil
}

func ContainerUpdate(ctx interface{}, data *grpc.ContainerData) error {

	if data == nil {
		return errors.New("Invalid input parameters")
	}

	logrus.Info("Container update message received...")

	ipcService := ctx.(*ipcService)

	// Create temporary container struct to be passed as reference to containerDB,
	// where the matching (real) container will identified and then updated.
	cntr := ipcService.css.ContainerCreate(
		data.Id,
		uint32(data.InitPid),
		0,
		data.Ctime,
		uint32(data.UidFirst),
		uint32(data.UidSize),
		uint32(data.GidFirst),
		uint32(data.GidSize),
	)

	err := ipcService.css.ContainerUpdate(cntr)
	if err != nil {
		return err
	}

	logrus.Info("Container update successfully completed.")

	return nil
}
