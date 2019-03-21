package main

import (
	"context"
	"log"
	"net"
	"time"

	"github.com/golang/protobuf/ptypes"
	pb "github.com/nestybox/sysvisor/sysvisor-protobuf"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

//
// File dealing with all the logic related to Sysvisorfs' external-communication
// (ipc) logic.
//

const (
	// TODO: Is there a better tcp-socket? Find out.
	port = ":50052"
)

type server struct {
	fs *sysvisorFS
}

func (s *server) ContainerRegistration(
	ctx context.Context,
	in *pb.ContainerData) (*pb.Response, error) {

	log.Println("gRPC Container Registration request received for container:",
		in.Id)

	// During container initialization, the provided creation-time doesn't
	// reflect a proper value, so we are expliciting setting a default value
	// here (zero) till a subsequent grpc message arrive with the expected
	// information.
	ctime := time.Time{}

	cs, err := newContainerState(
		in.Id,
		uint32(in.InitPid),
		in.Hostname,
		ctime,
		uint32(in.UidFirst),
		uint32(in.UidSize),
		uint32(in.GidFirst),
		uint32(in.GidSize),
	)
	if err != nil {
		return &pb.Response{Success: false}, nil
	}

	err = s.fs.pidInodeContainerMap.register(cs)
	if err != nil {
		return &pb.Response{Success: false}, nil
	}

	return &pb.Response{Success: true}, nil
}

func (s *server) ContainerUnregistration(
	ctx context.Context,
	in *pb.ContainerData) (*pb.Response, error) {

	log.Println("gRPC Container Unregistration request received for container:",
		in.Id)

	// Container creation-time attribute is irrelevant at unregistration phase.
	// Discard received value by initializing this attribute to zero.
	ctime := time.Time{}

	cs, err := newContainerState(
		in.Id,
		uint32(in.InitPid),
		in.Hostname,
		ctime,
		uint32(in.UidFirst),
		uint32(in.UidSize),
		uint32(in.GidFirst),
		uint32(in.GidSize),
	)
	if err != nil {
		return &pb.Response{Success: false}, nil
	}

	err = s.fs.pidInodeContainerMap.unregister(cs)
	if err != nil {
		return &pb.Response{Success: false}, nil
	}

	return &pb.Response{Success: true}, nil
}

func (s *server) ContainerUpdate(
	ctx context.Context,
	in *pb.ContainerData) (*pb.Response, error) {

	log.Println("gRPC ContainerStateUpdate message received for container:",
		in.Id)

	cTime, err := ptypes.Timestamp(in.Ctime)
	if err != nil {
		return nil, err
	}

	cs, err := newContainerState(
		in.Id,
		uint32(in.InitPid),
		in.Hostname,
		cTime,
		uint32(in.UidFirst),
		uint32(in.UidSize),
		uint32(in.GidFirst),
		uint32(in.GidSize),
	)
	if err != nil {
		return &pb.Response{Success: false}, nil
	}

	err = s.fs.pidInodeContainerMap.update(cs)
	if err != nil {
		return &pb.Response{Success: false}, nil
	}

	return &pb.Response{Success: true}, nil
}

func initGrpcServer(fs *sysvisorFS) {

	//
	// TODO: Change me to unix-socket instead: more secure and more efficient.
	//
	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	// Initializing grpc server
	s := grpc.NewServer()

	// Initializing sysvisorfs' grpc server
	sysvisorGrpcServer := &server{fs: fs}

	pb.RegisterContainerStateChannelServer(s, sysvisorGrpcServer)
	// Register reflection service on gRPC server.
	reflection.Register(s)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
