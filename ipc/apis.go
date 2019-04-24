package ipc

import (
	"errors"
	"log"
	"strconv"

	"github.com/nestybox/sysvisor/sysvisor-fs/domain"
	"github.com/nestybox/sysvisor/sysvisor-protobuf/sysvisorGrpc"
)

type ipcService struct {
	grpcServer *sysvisorGrpc.Server
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
	newService.grpcServer = sysvisorGrpc.NewServer(
		newService,
		&sysvisorGrpc.CallbacksMap{
			sysvisorGrpc.ContainerRegisterMessage:   ContainerRegister,
			sysvisorGrpc.ContainerUnregisterMessage: ContainerUnregister,
			sysvisorGrpc.ContainerUpdateMessage:     ContainerUpdate,
		})

	return newService
}

func (s *ipcService) Init() {
	go s.grpcServer.Init()
}

func ContainerRegister(ctx interface{}, data *sysvisorGrpc.ContainerData) error {

	if data == nil {
		return errors.New("Invalid input parameters")
	}

	log.Println("Container Registration: received Pid:", data.InitPid)

	ipcService := ctx.(*ipcService)

	// Identify the pidNsInode corresponding to this pid.
	tmpNode := ipcService.ios.NewIOnode(strconv.Itoa(int(data.InitPid)), 0)
	pidInode, err := ipcService.ios.PidNsInode(tmpNode)
	if err != nil {
		return err
	}

	cntr := &domain.Container{
		ID:       data.Id,
		InitPid:  uint32(data.InitPid),
		Hostname: data.Hostname,
		Ctime:    data.Ctime,
		UIDFirst: uint32(data.UidFirst),
		UIDSize:  uint32(data.UidSize),
		GIDFirst: uint32(data.GidFirst),
		GIDSize:  uint32(data.GidSize),
		PidInode: pidInode,
		Data:     make(map[string]map[string]string),
	}

	err = ipcService.css.ContainerAdd(cntr)
	if err != nil {
		return err
	}

	log.Println("Container registration successfully completed:", cntr.String())

	return nil
}

func ContainerUnregister(ctx interface{}, data *sysvisorGrpc.ContainerData) error {

	if data == nil {
		return errors.New("Invalid input parameters")
	}

	cntr := &domain.Container{
		ID:       data.Id,
		InitPid:  uint32(data.InitPid),
		Hostname: data.Hostname,
		Ctime:    data.Ctime,
		UIDFirst: uint32(data.UidFirst),
		UIDSize:  uint32(data.UidSize),
		GIDFirst: uint32(data.GidFirst),
		GIDSize:  uint32(data.GidSize),
	}

	ipcService := ctx.(*ipcService)
	err := ipcService.css.ContainerDelete(cntr)
	if err != nil {
		return err
	}

	log.Println("Container unregistration successfully completed:", cntr.String())

	return nil
}

func ContainerUpdate(ctx interface{}, data *sysvisorGrpc.ContainerData) error {

	if data == nil {
		return errors.New("Invalid input parameters")
	}

	cntr := &domain.Container{
		ID:       data.Id,
		InitPid:  uint32(data.InitPid),
		Hostname: data.Hostname,
		Ctime:    data.Ctime,
		UIDFirst: uint32(data.UidFirst),
		UIDSize:  uint32(data.UidSize),
		GIDFirst: uint32(data.GidFirst),
		GIDSize:  uint32(data.GidSize),
	}

	ipcService := ctx.(*ipcService)
	err := ipcService.css.ContainerUpdate(cntr)
	if err != nil {
		return err
	}

	log.Println("Container update successfully completed:", cntr.String())

	return nil
}
