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
	"io"
	"reflect"
	"testing"
	"time"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/mocks"
	"github.com/stretchr/testify/assert"
)

func Test_container_ID(t *testing.T) {

	var cs1 = &container{
		id: "cs1",
	}

	var cs2 = &container{
		id: "",
	}

	tests := []struct {
		name string
		c    *container
		want string
	}{
		// Regular case.
		{"1", cs1, "cs1"},

		// Lame testcase -- of course it works.
		{"2", cs2, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.c.ID(); got != tt.want {
				t.Errorf("container.ID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_container_InitPid(t *testing.T) {

	var cs1 = &container{
		initPid: 1111,
	}

	var cs2 = &container{
		initPid: 0,
	}

	tests := []struct {
		name string
		c    *container
		want uint32
	}{
		// Regular case.
		{"1", cs1, 1111},

		// Lame testcase -- of course it works.
		{"2", cs2, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.c.InitPid(); got != tt.want {
				t.Errorf("container.InitPid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_container_Ctime(t *testing.T) {

	var cs1 = &container{
		ctime: time.Date(2019, 05, 01, 0, 0, 0, 0, time.UTC),
	}

	var cs2 = &container{
		ctime: time.Time{},
	}

	tests := []struct {
		name string
		c    *container
		want time.Time
	}{
		// Regular case.
		{"1", cs1, time.Date(2019, 05, 01, 0, 0, 0, 0, time.UTC)},

		// Lame testcase -- of course it works.
		{"2", cs2, time.Time{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.c.Ctime(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("container.Ctime() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_container_SetCtime(t *testing.T) {

	var cs1 = &container{
		ctime: time.Date(2019, 05, 01, 0, 0, 0, 0, time.UTC),
	}

	type args struct {
		t time.Time
	}
	tests := []struct {
		name string
		c    *container
		args args
	}{
		// Regular case.
		{"1", cs1, args{time.Date(2019, 05, 01, 0, 0, 0, 0, time.UTC)}},

		// Lame testcase -- of course it works.
		{"2", cs1, args{time.Time{}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.c.SetCtime(tt.args.t)
		})

		assert.Equal(t, tt.args.t, tt.c.Ctime(), "ctime fields are not matching")
	}
}

func Test_container_SetData(t *testing.T) {

	var cs1 = &container{
		dataStore: make(map[string][]byte),
	}

	cs1.dataStore["/proc/cpuinfo"] = []byte("FOO")

	type args struct {
		name   string
		offset int64
		data   []byte
	}

	tests := []struct {
		name string
		c    *container
		args args
	}{
		// Insert new data record.
		{"1", cs1, args{"/proc/testing", 0, []byte("12345")}},

		// Update existing data record.
		{"2", cs1, args{"/proc/cpuinfo", 0, []byte("FOO \n BAR")}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.c.SetData(tt.args.name, tt.args.offset, tt.args.data)

			buf := make([]byte, 20)
			_, err := tt.c.Data(tt.args.name, 0, &buf)
			if err != nil && err != io.EOF {
				t.Errorf("Unexpected result during execution of testcase %v", tt.name)
			}

			assert.Equal(t, tt.args.data, buf, "data fields are not matching")
		})
	}
}

func Test_container_update(t *testing.T) {
	type fields struct {
		id            string
		initPid       uint32
		ctime         time.Time
		uidFirst      uint32
		uidSize       uint32
		gidFirst      uint32
		gidSize       uint32
		procRoPaths   []string
		procMaskPaths []string
		specPaths     map[string]struct{}
		dataStore     map[string][]byte
		initProc      domain.ProcessIface
		service       *containerStateService
	}
	f1 := fields{
		id:       "1",
		initPid:  1011,
		initProc: prs.ProcessCreate(1001, 0, 0),
	}

	// Create local css as it's required by cntr.update() method.
	css := &containerStateService{
		idTable:    nil,
		netnsTable: nil,
		fss:        fss,
		prs:        prs,
		ios:        ios,
		mts:        &mocks.MountServiceIface{},
	}

	type args struct {
		src *container
	}
	a1 := args{
		src: &container{
			id:            "1",
			initPid:       1011,
			ctime:         time.Time{},
			uidFirst:      1,
			uidSize:       65535,
			gidFirst:      1,
			gidSize:       65535,
			procRoPaths:   nil,
			procMaskPaths: nil,
			dataStore:     nil,
			service:       css,
		},
	}

	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{"1", f1, a1, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &container{
				id:            tt.fields.id,
				initPid:       tt.fields.initPid,
				ctime:         tt.fields.ctime,
				uidFirst:      tt.fields.uidFirst,
				uidSize:       tt.fields.uidSize,
				gidFirst:      tt.fields.gidFirst,
				gidSize:       tt.fields.gidSize,
				procRoPaths:   tt.fields.procRoPaths,
				procMaskPaths: tt.fields.procMaskPaths,
				dataStore:     tt.fields.dataStore,
				initProc:      tt.fields.initProc,
				service:       css,
			}

			c.service.MountService().(*mocks.MountServiceIface).On(
				"NewMountInfoParser", c, c.initProc, true, true, true).Return(nil, nil)

			if err := c.update(tt.args.src); (err != nil) != tt.wantErr {
				t.Errorf("container.update() error = %v, wantErr %v",
					err, tt.wantErr)
			}

			assert.Equal(t, c.initPid, tt.args.src.initPid)
			assert.Equal(t, c.ctime, tt.args.src.ctime)
			assert.Equal(t, c.uidFirst, tt.args.src.uidFirst)
			assert.Equal(t, c.uidSize, tt.args.src.uidSize)
			assert.Equal(t, c.gidFirst, tt.args.src.gidFirst)
			assert.Equal(t, c.gidSize, tt.args.src.gidSize)
		})
	}
}
