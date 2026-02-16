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

package sysboxFsGrpc

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/golang/protobuf/ptypes"
	pb "github.com/nestybox/sysbox-fs/sysbox-ipc/sysboxFsGrpc/sysboxFsProtobuf"
	"github.com/nestybox/sysbox-fs/sysbox-libs/formatter"
	"google.golang.org/grpc"

	"github.com/sirupsen/logrus"
)

var grpcTimeout time.Duration = 20 * time.Second

// Container info passed by the client to the server across the grpc channel
type ContainerData struct {
	Id            string
	Netns         string
	InitPid       int32
	Hostname      string
	Ctime         time.Time
	UidFirst      int32
	UidSize       int32
	GidFirst      int32
	GidSize       int32
	ProcRoPaths   []string
	ProcMaskPaths []string
}

func unixConnect(addr string, t time.Duration) (net.Conn, error) {
	unixAddr, err := net.ResolveUnixAddr("unix", sysFsGrpcSockAddr)
	conn, err := net.DialUnix("unix", nil, unixAddr)
	return conn, err
}

// Establishes grpc connection to sysbox-fs' remote-end.
func connect() (*grpc.ClientConn, error) {
	// Set up a connection to the server.
	// TODO: Secure me through TLS.
	conn, err := grpc.Dial(
		sysFsGrpcSockAddr,
		grpc.WithInsecure(),
		grpc.WithDialer(unixConnect),
	)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func containerDataToPbData(data *ContainerData) (*pb.ContainerData, error) {
	pbTime, err := ptypes.TimestampProto(data.Ctime)
	if err != nil {
		return nil, fmt.Errorf("time conversion error: %v", err)
	}

	return &pb.ContainerData{
		Id:            data.Id,
		Netns:         data.Netns,
		InitPid:       data.InitPid,
		Ctime:         pbTime,
		UidFirst:      data.UidFirst,
		UidSize:       data.UidSize,
		GidFirst:      data.GidFirst,
		GidSize:       data.GidSize,
		ProcRoPaths:   data.ProcRoPaths,
		ProcMaskPaths: data.ProcMaskPaths,
	}, nil
}

func pbDatatoContainerData(pbdata *pb.ContainerData) (*ContainerData, error) {
	cTime, err := ptypes.Timestamp(pbdata.Ctime)
	if err != nil {
		return nil, fmt.Errorf("time conversion error: %v", err)
	}

	return &ContainerData{
		Id:            pbdata.Id,
		Netns:         pbdata.Netns,
		InitPid:       pbdata.InitPid,
		Ctime:         cTime,
		UidFirst:      pbdata.UidFirst,
		UidSize:       pbdata.UidSize,
		GidFirst:      pbdata.GidFirst,
		GidSize:       pbdata.GidSize,
		ProcRoPaths:   pbdata.ProcRoPaths,
		ProcMaskPaths: pbdata.ProcMaskPaths,
	}, nil
}

// Pre-registers container creation in sysbox-fs. Notice that this
// is a blocking call that can potentially have a minor impact
// on container's boot-up speed.
func SendContainerPreRegistration(data *ContainerData) (err error) {
	// Set up sysbox-fs pipeline.
	conn, err := connect()
	if err != nil {
		return fmt.Errorf("failed to connect with sysbox-fs: %v", err)
	}
	defer conn.Close()

	cntrChanIntf := pb.NewSysboxStateChannelClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), grpcTimeout)
	defer cancel()

	pbData, err := containerDataToPbData(data)
	if err != nil {
		return fmt.Errorf("convertion to protobuf data failed: %v", err)
	}

	_, err = cntrChanIntf.ContainerPreRegistration(ctx, pbData)
	if err != nil {
		logrus.Warning("Container %s pre-registration error: %s",
			formatter.ContainerID{data.Id}, err)
		return fmt.Errorf("failed to pre-register container with sysbox-fs: %v", err)
	}

	return nil
}

// Registers container creation in sysbox-fs.
func SendContainerRegistration(data *ContainerData) (err error) {
	// Set up sysbox-fs pipeline.
	conn, err := connect()
	if err != nil {
		return fmt.Errorf("failed to connect with sysbox-fs: %v", err)
	}
	defer conn.Close()

	cntrChanIntf := pb.NewSysboxStateChannelClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), grpcTimeout)
	defer cancel()

	pbData, err := containerDataToPbData(data)
	if err != nil {
		return fmt.Errorf("convertion to protobuf data failed: %v", err)
	}

	_, err = cntrChanIntf.ContainerRegistration(ctx, pbData)
	if err != nil {
		logrus.Warning("Container %s registration error: %s",
			formatter.ContainerID{data.Id}, err)
		return fmt.Errorf("failed to register container with sysbox-fs: %v", err)
	}

	return nil
}

// Unregisters container from sysbox-fs.
func SendContainerUnregistration(data *ContainerData) (err error) {
	// Set up sysbox-fs pipeline.
	conn, err := connect()
	if err != nil {
		return fmt.Errorf("failed to connect with sysbox-fs: %v", err)
	}
	defer conn.Close()

	cntrChanIntf := pb.NewSysboxStateChannelClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), grpcTimeout)
	defer cancel()

	pbData, err := containerDataToPbData(data)
	if err != nil {
		return fmt.Errorf("convertion to protobuf data failed: %v", err)
	}

	_, err = cntrChanIntf.ContainerUnregistration(ctx, pbData)
	if err != nil {
		return fmt.Errorf("failed to unregister container with sysbox-fs: %v", err)
	}

	return nil
}

// Sends a container-update message to sysbox-fs end. At this point, we are
// only utilizing this message for a particular case, update the container
// creation-time attribute, but this function can serve more general purposes
// in the future.
func SendContainerUpdate(data *ContainerData) (err error) {
	// Set up sysbox-fs pipeline.
	conn, err := connect()
	if err != nil {
		return fmt.Errorf("failed to connect with sysbox-fs: %v", err)
	}
	defer conn.Close()

	cntrChanIntf := pb.NewSysboxStateChannelClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), grpcTimeout)
	defer cancel()

	pbData, err := containerDataToPbData(data)
	if err != nil {
		return fmt.Errorf("convertion to protobuf data failed: %v", err)
	}

	_, err = cntrChanIntf.ContainerUpdate(ctx, pbData)
	if err != nil {
		logrus.Warning("Container %s update error: %s",
			formatter.ContainerID{data.Id}, err)
		return fmt.Errorf("failed to send container-update message to ",
			"sysbox-fs: %v", err)
	}

	return nil
}

func GetMountpoint() (string, error) {
	var mpResp *pb.MountpointResp

	// Set up sysbox-fs pipeline.
	conn, err := connect()
	if err != nil {
		return "", fmt.Errorf("failed to connect with sysbox-fs: %v", err)
	}
	defer conn.Close()

	cntrChanIntf := pb.NewSysboxStateChannelClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), grpcTimeout)
	defer cancel()

	mpResp, err = cntrChanIntf.GetMountpoint(ctx, &pb.MountpointReq{})
	if err != nil {
		return "", fmt.Errorf("failed to get sysbox-fs mountpoint: %v", err)
	}

	return mpResp.GetMountpoint(), nil
}
