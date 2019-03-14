package main

import (
	"context"
	"log"
	"net"

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

	cs, err := newContainerState(
		in.Id,
		uint32(in.InitPid),
		in.Hostname,
		uint32(in.UidFirst),
		uint32(in.UidSize),
		uint32(in.GidFirst),
		uint32(in.GidSize),
	)
	if err != nil {
		return &pb.Response{Success: false}, nil
	}

	err = s.fs.pidInodeMap.register(cs)
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

	cs, err := newContainerState(
		in.Id,
		uint32(in.InitPid),
		in.Hostname,
		uint32(in.UidFirst),
		uint32(in.UidSize),
		uint32(in.GidFirst),
		uint32(in.GidSize),
	)
	if err != nil {
		return &pb.Response{Success: false}, nil
	}

	err = s.fs.pidInodeMap.unregister(cs)
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
