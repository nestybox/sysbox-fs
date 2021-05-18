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

package state

import (
	"io/ioutil"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/mocks"
	"github.com/nestybox/sysbox-fs/process"
	"github.com/nestybox/sysbox-fs/sysio"
	"github.com/sirupsen/logrus"
)

// Sysbox-fs global services for all state's pkg unit-tests.
var ios domain.IOServiceIface
var prs domain.ProcessServiceIface
var nss *mocks.NSenterServiceIface
var fss *mocks.FuseServerServiceIface
var hds *mocks.HandlerServiceIface
var mts *mocks.MountServiceIface

func TestMain(m *testing.M) {

	// Disable log generation during UT.
	logrus.SetOutput(ioutil.Discard)

	//
	// Test-cases common settings.
	//
	ios = sysio.NewIOService(domain.IOMemFileService)
	prs = process.NewProcessService()
	nss = &mocks.NSenterServiceIface{}
	hds = &mocks.HandlerServiceIface{}
	fss = &mocks.FuseServerServiceIface{}
	mts = &mocks.MountServiceIface{}

	prs.Setup(ios)

	// Run test-suite.
	m.Run()
}

func Test_containerStateService_Setup(t *testing.T) {
	type fields struct {
		RWMutex     sync.RWMutex
		idTable     map[string]*container
		usernsTable map[domain.Inode][]*container
		fss         domain.FuseServerServiceIface
		prs         domain.ProcessServiceIface
		ios         domain.IOServiceIface
		mts         domain.MountServiceIface
	}

	var f1 = fields{
		idTable:     make(map[string]*container),
		usernsTable: make(map[domain.Inode][]*container),
		fss:         fss,
		prs:         prs,
		ios:         ios,
	}

	type args struct {
		fss domain.FuseServerServiceIface
		prs domain.ProcessServiceIface
		ios domain.IOServiceIface
		mts domain.MountServiceIface
	}

	a1 := args{
		fss: fss,
		prs: prs,
		ios: ios,
		mts: mts,
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
			css := &containerStateService{
				RWMutex:     tt.fields.RWMutex,
				idTable:     tt.fields.idTable,
				usernsTable: tt.fields.usernsTable,
				fss:         tt.fields.fss,
				prs:         tt.fields.prs,
				ios:         tt.fields.ios,
				mts:         tt.fields.mts,
			}
			css.Setup(tt.args.fss, tt.args.prs, tt.args.ios, tt.args.mts)
		})
	}
}

func Test_containerStateService_ContainerCreate(t *testing.T) {

	type fields struct {
		idTable     map[string]*container
		usernsTable map[domain.Inode][]*container
		fss         domain.FuseServerServiceIface
		prs         domain.ProcessServiceIface
		ios         domain.IOServiceIface
		mts         domain.MountServiceIface
	}

	var f1 = fields{
		idTable:     make(map[string]*container),
		usernsTable: make(map[domain.Inode][]*container),
		fss:         fss,
		prs:         prs,
		ios:         ios,
		mts:         mts,
	}

	css := &containerStateService{
		idTable:     f1.idTable,
		usernsTable: f1.usernsTable,
		fss:         f1.fss,
		prs:         f1.prs,
		ios:         f1.ios,
		mts:         f1.mts,
	}
	type args struct {
		id            string
		initPid       uint32
		ctime         time.Time
		uidFirst      uint32
		uidSize       uint32
		gidFirst      uint32
		gidSize       uint32
		procRoPaths   []string
		procMaskPaths []string
	}

	// Manually create a container to compare with.
	var c1 = &container{
		id:            "1",
		initPid:       1001,
		ctime:         time.Time{},
		uidFirst:      1,
		uidSize:       65535,
		gidFirst:      1,
		gidSize:       65535,
		procRoPaths:   nil,
		procMaskPaths: nil,
		dataStore:     nil,
		initProc:      nil,
		service:       css,
	}

	tests := []struct {
		name   string
		fields fields
		args   args
		want   domain.ContainerIface
	}{
		//
		// Testcase 1: Compare previously create container with a new one to be
		// built through the container's constructor method. They should fully
		// match.
		//
		{"1", f1, args{
			c1.id,
			c1.initPid,
			c1.ctime,
			c1.uidFirst,
			c1.uidSize,
			c1.gidFirst,
			c1.gidSize,
			nil,
			nil,
		}, c1},
	}

	//
	// Testcase executions.
	//
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := css.ContainerCreate(
				tt.args.id,
				tt.args.initPid,
				tt.args.ctime,
				tt.args.uidFirst,
				tt.args.uidSize,
				tt.args.gidFirst,
				tt.args.gidSize,
				tt.args.procRoPaths,
				tt.args.procMaskPaths,
				css); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("containerStateService.ContainerCreate() = %v, want %v",
					got, tt.want)
			}
		})
	}
}

func Test_containerStateService_ContainerPreRegister(t *testing.T) {

	type fields struct {
		idTable     map[string]*container
		usernsTable map[domain.Inode][]*container
		fss         domain.FuseServerServiceIface
		prs         domain.ProcessServiceIface
		ios         domain.IOServiceIface
		mts         domain.MountServiceIface
	}

	var f1 = fields{
		idTable:     make(map[string]*container),
		usernsTable: make(map[domain.Inode][]*container),
		fss:         fss,
		prs:         prs,
		ios:         ios,
		mts:         mts,
	}

	css := &containerStateService{
		idTable:     f1.idTable,
		usernsTable: f1.usernsTable,
		fss:         f1.fss,
		prs:         f1.prs,
		ios:         f1.ios,
		mts:         f1.mts,
	}

	var c1 = &container{
		id:      "c1",
		service: css,
	}

	var c2 = &container{
		id:      "c2",
		service: css,
	}

	type args struct {
		id string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
		prepare func()
	}{
		{
			//
			// Test-case 1: Pre-register a new container.
			//
			name:    "1",
			fields:  f1,
			args:    args{"c1"},
			wantErr: false,
			prepare: func() {

				css.FuseServerService().(*mocks.FuseServerServiceIface).On(
					"CreateFuseServer", c1).Return(nil)
			},
		},
		{
			//
			// Test-case 2: Pre-register an already-present container (with
			// matching container ID). Error expected.
			//
			name:    "2",
			fields:  f1,
			args:    args{"c2"},
			wantErr: true,
			prepare: func() {

				f1.idTable[c2.id] = c2
				css.FuseServerService().(*mocks.FuseServerServiceIface).On(
					"CreateFuseServer", c2).Return(nil)
			},
		},
	}

	//
	// Testcase executions.
	//
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Prepare the mocks.
			if tt.prepare != nil {
				tt.prepare()
			}

			if err := css.ContainerPreRegister(tt.args.id, ""); (err != nil) != tt.wantErr {
				t.Errorf("containerStateService.ContainerPreRegister() error = %v, wantErr %v",
					err, tt.wantErr)
			}
		})
	}
}

func Test_containerStateService_ContainerRegister(t *testing.T) {

	type fields struct {
		RWMutex     sync.RWMutex
		idTable     map[string]*container
		usernsTable map[domain.Inode][]*container
		fss         domain.FuseServerServiceIface
		prs         domain.ProcessServiceIface
		ios         domain.IOServiceIface
		mts         domain.MountServiceIface
	}

	var f1 = fields{
		idTable:     make(map[string]*container),
		usernsTable: make(map[domain.Inode][]*container),
		fss:         fss,
		prs:         prs,
		ios:         ios,
		mts:         mts,
	}

	var c1 = &container{
		id:       "c1",
		initPid:  1001,
		initProc: f1.prs.ProcessCreate(1001, 0, 0),
	}

	var c2 = &container{
		id: "c2",
	}

	var c3 = &container{
		id:       "c3",
		initPid:  3003,
		initProc: f1.prs.ProcessCreate(3003, 0, 0),
	}

	var c4 = &container{
		id:       "c4",
		initPid:  4004,
		initProc: f1.prs.ProcessCreate(4004, 0, 0),
	}

	type args struct {
		c domain.ContainerIface
	}

	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
		prepare func(css *containerStateService)
	}{
		{
			//
			// Test-case 1: Register a pre-registered container with valid
			// user-ns.
			//
			name:    "1",
			fields:  f1,
			args:    args{c1},
			wantErr: false,
			prepare: func(css *containerStateService) {

				c1.service = css

				c1.InitProc().CreateNsInodes(123456)

				f1.idTable[c1.id] = c1

				c1.service.MountService().(*mocks.MountServiceIface).On(
					"NewMountInfoParser", c1, c1.initProc, true, true, true).Return(nil, nil)
			},
		},
		{
			//
			// Test-case 2: Register a non-pre-registered container. Error
			// expected.
			//
			name:    "2",
			fields:  f1,
			args:    args{c2},
			wantErr: true,
			prepare: func(css *containerStateService) {},
		},
		{
			//
			// Test-case 3: Register a pre-registered container with missing
			// user-ns inode (i.e. missing /proc/pid/ns/<namespaces>). Error
			// expected.
			//
			name:    "3",
			fields:  f1,
			args:    args{c3},
			wantErr: true,
			prepare: func(css *containerStateService) {

				c3.service = css
				f1.idTable[c3.id] = c3

				css.MountService().(*mocks.MountServiceIface).On(
					"NewMountInfoParser", c3, c3.initProc, true, true, true).Return(nil, nil)
			},
		},
		{
			// TODO: FIXME

			//
			// Test-case 4: Register a pre-registered container with an existing
			// user-ns inode (i.e. /proc/pid/ns/<namespaces>). However, this inode
			// value is present in usernsTable by the time the registration begins,
			// which is an unexpected error, as it indicates "overlapping"
			// condition. Error expected.
			//
			name:    "4",
			fields:  f1,
			args:    args{c4},
			wantErr: true,
			prepare: func(css *containerStateService) {

				c4.service = css

				c4.InitProc().CreateNsInodes(123456)
				inode, _ := c4.InitProc().UserNsInode()

				f1.idTable[c4.id] = c4
				f1.usernsTable[inode] = []*container{c4} // <-- unexpected instruction during registration

				c4.service.MountService().(*mocks.MountServiceIface).On(
					"NewMountInfoParser", c4, c4.initProc, true, true, true).Return(nil, nil)
			},
		},
	}

	//
	// Testcase executions.
	//
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			css := &containerStateService{
				RWMutex:     tt.fields.RWMutex,
				idTable:     tt.fields.idTable,
				usernsTable: tt.fields.usernsTable,
				fss:         tt.fields.fss,
				prs:         tt.fields.prs,
				ios:         tt.fields.ios,
				mts:         tt.fields.mts,
			}

			// Initialize memory-based mock FS.
			css.ios.RemoveAllIOnodes()

			// Prepare the mocks.
			if tt.prepare != nil {
				tt.prepare(css)
			}

			if err := css.ContainerRegister(tt.args.c); (err != nil) != tt.wantErr {
				t.Errorf("containerStateService.ContainerRegister() error = %v, wantErr %v",
					err, tt.wantErr)
			}
		})
	}
}

func Test_containerStateService_ContainerUpdate(t *testing.T) {
	type fields struct {
		RWMutex     sync.RWMutex
		idTable     map[string]*container
		usernsTable map[domain.Inode][]*container
		fss         domain.FuseServerServiceIface
		prs         domain.ProcessServiceIface
		ios         domain.IOServiceIface
		mts         domain.MountServiceIface
	}

	var f1 = fields{
		idTable:     make(map[string]*container),
		usernsTable: make(map[domain.Inode][]*container),
		fss:         fss,
		prs:         prs,
		ios:         ios,
		mts:         mts,
	}

	var c1 = &container{
		id:       "c1",
		initProc: f1.prs.ProcessCreate(1001, 0, 0),
	}
	f1.idTable[c1.id] = c1

	var c2 = &container{
		id:       "c2",
		initProc: f1.prs.ProcessCreate(2002, 0, 0),
	}

	type args struct {
		c domain.ContainerIface
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
		prepare func(css *containerStateService)
	}{
		{
			//
			// Test-case 1: Update a properly registered container.
			//
			name:    "1",
			fields:  f1,
			args:    args{c1},
			wantErr: false,
			prepare: func(css *containerStateService) {

				c1.service = css

				c1.InitProc().CreateNsInodes(123456)
				inode, _ := c1.InitProc().UserNsInode()

				f1.idTable[c1.id] = c1
				f1.usernsTable[inode] = []*container{c1}

				c1.service.MountService().(*mocks.MountServiceIface).On(
					"NewMountInfoParser", c1, c1.initProc, true, true, true).Return(nil, nil)
			},
		},
		{
			//
			// Test-case 2: Update a container whose container-ID is not present
			// in the idTable. Error expected.
			//
			name:    "2",
			fields:  f1,
			args:    args{c2},
			wantErr: true,
			prepare: func(css *containerStateService) {

				c2.service = css

				c2.InitProc().CreateNsInodes(123456)
				inode, _ := c2.InitProc().UserNsInode()

				f1.usernsTable[inode] = []*container{c2}

				c2.service.MountService().(*mocks.MountServiceIface).On(
					"NewMountInfoParser", c2, c2.initProc, true, true, true).Return(nil, nil)
			},
		},
	}

	//
	// Testcase executions.
	//
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			css := &containerStateService{
				RWMutex:     tt.fields.RWMutex,
				idTable:     tt.fields.idTable,
				usernsTable: tt.fields.usernsTable,
				fss:         tt.fields.fss,
				prs:         tt.fields.prs,
				ios:         tt.fields.ios,
				mts:         tt.fields.mts,
			}

			// Initialize memory-based mock FS.
			css.ios.RemoveAllIOnodes()

			// Prepare the mocks.
			if tt.prepare != nil {
				tt.prepare(css)
			}

			if err := css.ContainerUpdate(tt.args.c); (err != nil) != tt.wantErr {
				t.Errorf("containerStateService.ContainerUpdate() error = %v, wantErr %v",
					err, tt.wantErr)
			}
		})
	}
}

func Test_containerStateService_ContainerUnregister(t *testing.T) {
	type fields struct {
		RWMutex     sync.RWMutex
		idTable     map[string]*container
		usernsTable map[domain.Inode][]*container
		fss         domain.FuseServerServiceIface
		prs         domain.ProcessServiceIface
		ios         domain.IOServiceIface
	}

	var f1 = fields{
		idTable:     make(map[string]*container),
		usernsTable: make(map[domain.Inode][]*container),
		fss:         fss,
		prs:         prs,
		ios:         ios,
	}

	var c1 = &container{
		id:       "c1",
		initProc: f1.prs.ProcessCreate(1001, 0, 0),
	}

	var c2 = &container{
		id:       "c2",
		initProc: f1.prs.ProcessCreate(2002, 0, 0),
	}

	var c3 = &container{
		id:       "c3",
		initProc: f1.prs.ProcessCreate(3003, 0, 0),
	}

	var c4 = &container{
		id:       "c4",
		initProc: f1.prs.ProcessCreate(4004, 0, 0),
	}

	type args struct {
		c domain.ContainerIface
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
		prepare func(css *containerStateService)
	}{
		{
			//
			// Test-case 1: Unregister a valid (properly registered) container.
			//
			name:    "1",
			fields:  f1,
			args:    args{c1},
			wantErr: false,
			prepare: func(css *containerStateService) {

				c1.InitProc().CreateNsInodes(123456)
				inode, _ := c1.InitProc().UserNsInode()

				c1.service = css

				f1.idTable[c1.id] = c1
				f1.usernsTable[inode] = []*container{c1}

				css.FuseServerService().(*mocks.FuseServerServiceIface).On(
					"DestroyFuseServer", c1.id).Return(nil)
			},
		},
		{
			//
			// Test-case 2: Unregister a container with an id not present in
			// idTable. Error expected.
			//
			name:    "2",
			fields:  f1,
			args:    args{c2},
			wantErr: true,
			prepare: func(css *containerStateService) {

				c2.initProc.CreateNsInodes(123456)
				inode, _ := c2.InitProc().UserNsInode()

				c2.service = css

				f1.usernsTable[inode] = []*container{c2}
			},
		},
		{
			//
			// Test-case 3: Unregister a container with valid ID but with missing
			// user-ns. Error expected.
			//
			name:    "3",
			fields:  f1,
			args:    args{c3},
			wantErr: true,
			prepare: func(css *containerStateService) {

				c3.service = css

				f1.idTable[c3.id] = c3
			},
		},
		{
			//
			// Test-case 4: Unregister a container with valid ID and present
			// (but not valid) user-ns entry. Error expected.
			//
			name:    "4",
			fields:  f1,
			args:    args{c4},
			wantErr: true,
			prepare: func(css *containerStateService) {

				c4.InitProc().CreateNsInodes(123456)
				inode, _ := c4.InitProc().UserNsInode()

				c4.service = css

				f1.idTable[c4.id] = c4

				// Artificial error to exercise all code paths -- can't happen
				// w/o a memory corruption bug or alike, under no other
				//circumstance this would be ever reproduced.
				f1.usernsTable[inode] = []*container{c3} // <-- see we're pointing to c3 and not c4
			},
		},
	}

	//
	// Testcase executions.
	//
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			css := &containerStateService{
				RWMutex:     tt.fields.RWMutex,
				idTable:     tt.fields.idTable,
				usernsTable: tt.fields.usernsTable,
				fss:         tt.fields.fss,
				prs:         tt.fields.prs,
				ios:         tt.fields.ios,
			}

			// Initialize memory-based mock FS.
			css.ios.RemoveAllIOnodes()

			// Prepare the mocks.
			if tt.prepare != nil {
				tt.prepare(css)
			}

			if err := css.ContainerUnregister(tt.args.c); (err != nil) != tt.wantErr {
				t.Errorf("containerStateService.ContainerUnregister() error = %v, wantErr %v",
					err, tt.wantErr)
			}
		})
	}
}

func Test_containerStateService_ContainerLookupById(t *testing.T) {
	type fields struct {
		RWMutex     sync.RWMutex
		idTable     map[string]*container
		usernsTable map[domain.Inode][]*container
		fss         domain.FuseServerServiceIface
		prs         domain.ProcessServiceIface
		ios         domain.IOServiceIface
	}

	var f1 = fields{
		idTable:     make(map[string]*container),
		usernsTable: make(map[domain.Inode][]*container),
		fss:         fss,
		prs:         prs,
		ios:         ios,
	}

	var c1 = &container{
		id: "c1",
	}
	f1.idTable[c1.id] = c1

	type args struct {
		id string
	}

	tests := []struct {
		name   string
		fields fields
		args   args
		want   domain.ContainerIface
	}{
		// Lookup a valid/existing container.
		{"1", f1, args{"c1"}, c1},

		// Lookup a container with no matching entry in the idTable.
		// Error expected.
		{"2", f1, args{"c2"}, nil},
	}

	//
	// Testcase executions.
	//
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			css := &containerStateService{
				RWMutex:     tt.fields.RWMutex,
				idTable:     tt.fields.idTable,
				usernsTable: tt.fields.usernsTable,
				fss:         tt.fields.fss,
				prs:         tt.fields.prs,
				ios:         tt.fields.ios,
			}

			if got := css.ContainerLookupById(tt.args.id); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("containerStateService.ContainerLookupById() = %v, want %v",
					got, tt.want)
			}
		})
	}
}
