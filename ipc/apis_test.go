//
// Copyright 2019-2021 Nestybox, Inc.
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

package ipc_test

import (
	"errors"
	"io/ioutil"
	"reflect"
	"testing"
	"time"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/ipc"
	"github.com/nestybox/sysbox-fs/mocks"
	"github.com/nestybox/sysbox-fs/state"
	grpc "github.com/nestybox/sysbox-ipc/sysboxFsGrpc"
	"github.com/sirupsen/logrus"
)

// Sysbox-fs global services for all state's pkg unit-tests.
var css *mocks.ContainerStateServiceIface

func TestMain(m *testing.M) {

	// Disable log generation during UT.
	logrus.SetOutput(ioutil.Discard)

	//
	// Test-cases common settings.
	//
	css = &mocks.ContainerStateServiceIface{}
	css.On("Setup", nil, nil, nil).Return(nil)

	// Run test-suite.
	m.Run()
}

func TestNewIpcService(t *testing.T) {
	tests := []struct {
		name string
		want domain.IpcServiceIface
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ipc.NewIpcService(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewIpcService() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_ipcService_Setup(t *testing.T) {
	type fields struct {
		grpcServer *grpc.Server
		css        domain.ContainerStateServiceIface
		prs        domain.ProcessServiceIface
		ios        domain.IOServiceIface
		fuseMp     string
	}

	var f1 = fields{
		grpcServer: nil,
		css:        css,
		prs:        nil,
		ios:        nil,
		fuseMp:     "/var/lib/sysboxfs",
	}

	type args struct {
		css    domain.ContainerStateServiceIface
		prs    domain.ProcessServiceIface
		ios    domain.IOServiceIface
		fuseMp string
	}
	var a1 = args{
		css:    css,
		prs:    nil,
		ios:    nil,
		fuseMp: "/var/lib/sysboxfs",
	}

	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{"1", f1, a1},
	}

	//
	// Testcase executions.
	//
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ips := ipc.NewIpcService()
			ips.Setup(tt.args.css, tt.args.prs, tt.args.ios, tt.args.fuseMp)
		})
	}
}

func Test_ipcService_Init(t *testing.T) {
	type fields struct {
		grpcServer *grpc.Server
		css        domain.ContainerStateServiceIface
		prs        domain.ProcessServiceIface
		ios        domain.IOServiceIface
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ips := ipc.NewIpcService()
			if err := ips.Init(); (err != nil) != tt.wantErr {
				t.Errorf("ipcService.Init() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestContainerPreRegister(t *testing.T) {
	type args struct {
		ctx  interface{}
		data *grpc.ContainerData
	}

	var ctx = ipc.NewIpcService()
	ctx.Setup(css, nil, nil, "/var/lib/sysboxfs")

	var a1 = args{
		ctx: ctx,
		data: &grpc.ContainerData{
			Id:    "c1",
			Netns: "",
		},
	}

	tests := []struct {
		name    string
		args    args
		wantErr bool
		prepare func()
	}{
		{
			//
			// Test-case 1: Proper pre-registration request. No errors expected.
			//
			name:    "1",
			args:    a1,
			wantErr: false,
			prepare: func() {
				css.On("ContainerPreRegister", a1.data.Id, a1.data.Netns).Return(nil)
			},
		},
		{
			//
			// Test-case 2: Verify proper behavior during css' pre-registration
			// error.
			//
			name:    "2",
			args:    a1,
			wantErr: true,
			prepare: func() {
				css.On("ContainerPreRegister", a1.data.Id, a1.data.Netns).Return(
					errors.New("Container pre-registration error: container %s already present"))
			},
		},
	}

	//
	// Testcase executions.
	//
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Reset mock expectations from previous iterations.
			css.ExpectedCalls = nil

			// Prepare the mocks.
			if tt.prepare != nil {
				tt.prepare()
			}

			if err := ipc.ContainerPreRegister(tt.args.ctx, tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("ContainerPreRegister() error = %v, wantErr %v", err, tt.wantErr)
			}

			// Ensure that mocks were properly invoked.
			css.AssertExpectations(t)
		})
	}
}

func TestContainerRegister(t *testing.T) {
	type args struct {
		ctx  interface{}
		data *grpc.ContainerData
	}

	var c1 domain.ContainerIface

	var ctx = ipc.NewIpcService()
	ctx.Setup(css, nil, nil, "/var/lib/sysboxfs")

	var a1 = args{
		ctx: ctx,
		data: &grpc.ContainerData{
			Id: "c1",
		},
	}

	tests := []struct {
		name    string
		args    args
		wantErr bool
		prepare func()
	}{
		{
			//
			// Test-case 1: Proper pre-registration request. No errors expected.
			//
			name:    "1",
			args:    a1,
			wantErr: false,
			prepare: func() {
				css.On("ContainerCreate",
					a1.data.Id,
					uint32(a1.data.InitPid),
					a1.data.Ctime,
					uint32(a1.data.UidFirst),
					uint32(a1.data.UidSize),
					uint32(a1.data.GidFirst),
					uint32(a1.data.GidSize),
					a1.data.ProcRoPaths,
					a1.data.ProcMaskPaths,
					css).Return(c1)

				css.On("ContainerRegister", c1).Return(nil)
			},
		},
		{
			//
			// Test-case 2: Verify proper behavior during css' pre-registration
			// error.
			//
			name:    "2",
			args:    a1,
			wantErr: true,
			prepare: func() {

				css.On("ContainerCreate",
					a1.data.Id,
					uint32(a1.data.InitPid),
					a1.data.Ctime,
					uint32(a1.data.UidFirst),
					uint32(a1.data.UidSize),
					uint32(a1.data.GidFirst),
					uint32(a1.data.GidSize),
					a1.data.ProcRoPaths,
					a1.data.ProcMaskPaths,
					css).Return(c1)

				css.On("ContainerRegister", c1).Return(
					errors.New("registration error found"))
			},
		},
	}

	//
	// Testcase executions.
	//
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Reset mock expectations from previous iterations.
			css.ExpectedCalls = nil

			// Prepare the mocks.
			if tt.prepare != nil {
				tt.prepare()
			}

			if err := ipc.ContainerRegister(tt.args.ctx, tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("ContainerRegister() error = %v, wantErr %v", err, tt.wantErr)
			}

			// Ensure that mocks were properly invoked.
			css.AssertExpectations(t)
		})
	}
}

func TestContainerUnregister(t *testing.T) {
	type args struct {
		ctx  interface{}
		data *grpc.ContainerData
	}

	var c1 = state.NewContainerStateService().ContainerCreate(
		"c1",
		1001,
		time.Time{},
		231072,
		65535,
		231072,
		65535,
		nil,
		nil,
		nil,
	)

	var ctx = ipc.NewIpcService()
	ctx.Setup(css, nil, nil, "/var/lib/sysboxfs")

	var a1 = args{
		ctx: ctx,
		data: &grpc.ContainerData{
			Id: "c1",
		},
	}

	tests := []struct {
		name    string
		args    args
		wantErr bool
		prepare func()
	}{
		{
			//
			// Test-case 1: Proper pre-registration request. No errors expected.
			//
			name:    "1",
			args:    a1,
			wantErr: false,
			prepare: func() {

				css.On("ContainerLookupById", a1.data.Id).Return(c1)
				css.On("ContainerUnregister", c1).Return(nil)
			},
		},
		{
			//
			// Test-case 2: Verify proper behavior during css' pre-registration
			// error.
			//
			name:    "2",
			args:    a1,
			wantErr: true,
			prepare: func() {
				css.On("ContainerLookupById", a1.data.Id).Return(nil)
			},
		},
	}

	//
	// Testcase executions.
	//
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Reset mock expectations from previous iterations.
			css.ExpectedCalls = nil

			// Prepare the mocks.
			if tt.prepare != nil {
				tt.prepare()
			}

			if err := ipc.ContainerUnregister(tt.args.ctx, tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("ContainerUnregister() error = %v, wantErr %v", err, tt.wantErr)
			}

			// Ensure that mocks were properly invoked.
			css.AssertExpectations(t)
		})
	}
}

func TestContainerUpdate(t *testing.T) {
	type args struct {
		ctx  interface{}
		data *grpc.ContainerData
	}

	var c1 domain.ContainerIface

	var ctx = ipc.NewIpcService()
	ctx.Setup(css, nil, nil, "/var/lib/sysboxfs")

	var a1 = args{
		ctx: ctx,
		data: &grpc.ContainerData{
			Id: "c1",
		},
	}

	tests := []struct {
		name    string
		args    args
		wantErr bool
		prepare func()
	}{
		{
			//
			// Test-case 1: Proper pre-registration request. No errors expected.
			//
			name:    "1",
			args:    a1,
			wantErr: false,
			prepare: func() {

				css.On("ContainerCreate",
					a1.data.Id,
					uint32(a1.data.InitPid),
					a1.data.Ctime,
					uint32(a1.data.UidFirst),
					uint32(a1.data.UidSize),
					uint32(a1.data.GidFirst),
					uint32(a1.data.GidSize),
					a1.data.ProcRoPaths,
					a1.data.ProcMaskPaths,
					css).Return(c1)

				css.On("ContainerUpdate", c1).Return(nil)
			},
		},
		{
			//
			// Test-case 2: Verify proper behavior during css' pre-registration
			// error.
			//
			name:    "2",
			args:    a1,
			wantErr: true,
			prepare: func() {

				css.On("ContainerCreate",
					a1.data.Id,
					uint32(a1.data.InitPid),
					a1.data.Ctime,
					uint32(a1.data.UidFirst),
					uint32(a1.data.UidSize),
					uint32(a1.data.GidFirst),
					uint32(a1.data.GidSize),
					a1.data.ProcRoPaths,
					a1.data.ProcMaskPaths,
					css).Return(c1)

				css.On("ContainerUpdate", c1).Return(
					errors.New("registration error found"))
			},
		},
	}

	//
	// Testcase executions.
	//
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Reset mock expectations from previous iterations.
			css.ExpectedCalls = nil

			// Prepare the mocks.
			if tt.prepare != nil {
				tt.prepare()
			}

			if err := ipc.ContainerUpdate(tt.args.ctx, tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("ContainerUpdate() error = %v, wantErr %v", err, tt.wantErr)
			}

			// Ensure that mocks were properly invoked.
			css.AssertExpectations(t)
		})
	}
}
