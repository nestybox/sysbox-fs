package ipc

import (
	"errors"
	"log"
	"strconv"

	"github.com/nestybox/sysvisor-fs/domain"
	"github.com/nestybox/sysvisor-ipc/sysvisorFsGrpc"
)

type ipcService struct {
	grpcServer *sysvisorFsGrpc.Server
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
	newService.grpcServer = sysvisorFsGrpc.NewServer(
		newService,
		&sysvisorFsGrpc.CallbacksMap{
			sysvisorFsGrpc.ContainerRegisterMessage:   ContainerRegister,
			sysvisorFsGrpc.ContainerUnregisterMessage: ContainerUnregister,
			sysvisorFsGrpc.ContainerUpdateMessage:     ContainerUpdate,
		})

	return newService
}

func (s *ipcService) Init() {
	go s.grpcServer.Init()
}

func ContainerRegister(ctx interface{}, data *sysvisorFsGrpc.ContainerData) error {

	if data == nil {
		return errors.New("Invalid input parameters")
	}

	log.Println("Container Registration: received Pid:", data.InitPid)

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
		data.Hostname,
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

	log.Println("Container registration successfully completed.")

	return nil
}

func ContainerUnregister(ctx interface{}, data *sysvisorFsGrpc.ContainerData) error {

	if data == nil {
		return errors.New("Invalid input parameters")
	}

	ipcService := ctx.(*ipcService)

	// Create temporary container struct to be passed as reference to containerDB,
	// where the matching (real) container will be identified and then eliminated.
	cntr := ipcService.css.ContainerCreate(
		data.Id,
		uint32(data.InitPid),
		data.Hostname,
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

	log.Println("Container unregistration successfully completed.")

	return nil
}

func ContainerUpdate(ctx interface{}, data *sysvisorFsGrpc.ContainerData) error {

	if data == nil {
		return errors.New("Invalid input parameters")
	}

	ipcService := ctx.(*ipcService)

	// Create temporary container struct to be passed as reference to containerDB,
	// where the matching (real) container will identified and then updated.
	cntr := ipcService.css.ContainerCreate(
		data.Id,
		uint32(data.InitPid),
		data.Hostname,
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

	log.Println("Container update successfully completed.")

	return nil
}
