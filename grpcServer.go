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

type server struct{}

func (s *server) ContainerRegistration(
	ctx context.Context,
	in *pb.ContainerData) (*pb.Response, error) {

	log.Println("gRPC Container Registration request received for container:",
		in.Id)

	//
	// TODO: Move this code somewhere else -- cTime won't be coming as part of
	// the registration process.
	//
	//cTime, err := ptypes.Timestamp(in.Ctime)
	//if err != nil {
	//	return nil, err
	//}

	cntr, err := NewContainerState(
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

	err = cntr.register()
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

	cntr, ok := ContainerStateMapGlobal.lookup(in.Id)
	if !ok {
		return &pb.Response{Success: false}, nil
	}

	err := cntr.unregister()
	if err != nil {
		return &pb.Response{Success: false}, nil
	}

	return &pb.Response{Success: true}, nil
}

func init_grpc_server() {

	//
	// TODO: Change me to unix-socket instead: more secure and more efficient.
	//
	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	// Initializing grpc server
	s := grpc.NewServer()

	pb.RegisterContainerStateChannelServer(s, &server{})
	// Register reflection service on gRPC server.
	reflection.Register(s)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
