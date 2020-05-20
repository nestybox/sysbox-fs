//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

package state

import (
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/nestybox/sysbox-fs/domain"
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

func Test_container_Data(t *testing.T) {

	var cs1 = &container{
		dataStore: map[string](map[string]string){
			"/proc/uptime":  {"uptime": "100"},
			"/proc/cpuinfo": {"cpuinfo": "foo \n bar"},
		},
	}

	var cs2 = &container{}

	type args struct {
		path string
		name string
	}
	tests := []struct {
		name  string
		c     *container
		args  args
		want  string
		want1 bool
	}{
		// Single-line data.
		{"1", cs1, args{"/proc/uptime", "uptime"}, "100", true},

		// Multi-line data.
		{"2", cs1, args{"/proc/cpuinfo", "cpuinfo"}, "foo \n bar", true},

		// Missing specific (handler) info being requested. 'False' result
		// expected.
		{"3", cs1, args{"/proc/missing", "missing"}, "", false},

		// Missing the entire dataStorage map. 'False' result expected.
		{"4", cs2, args{"/proc/cpuinfo", "cpuinfo"}, "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := tt.c.Data(tt.args.path, tt.args.name)
			if got != tt.want {
				t.Errorf("container.Data() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("container.Data() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func Test_container_String(t *testing.T) {

	var cs = &container{
		id:      "1",
		initPid: 1001,
		ctime:   time.Time{},
	}

	var expectedResult = `
		 id: 1
		 initPid: 1001
		 ctime: 0001-01-01 00:00:00 +0000 UTC
		 UID: 0
		 GID: 0`

	tests := []struct {
		name string
		c    *container
		want string
	}{
		{"1", cs, expectedResult},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.c.String(); got != tt.want {
				t.Errorf("container.String() = %v, want %v", got, tt.want)
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
		dataStore: map[string](map[string]string){
			"/proc/cpuinfo": {"cpuinfo": "foo \n bar"},
		},
	}

	var cs2 = &container{}

	type args struct {
		path string
		name string
		data string
	}
	tests := []struct {
		name string
		c    *container
		args args
	}{
		// Insert new data record.
		{"1", cs1, args{"/proc/testing", "testing", "12345"}},

		// Update existing data record.
		{"2", cs1, args{"/proc/cpuinfo", "cpuinfo", "FOO \n BAR"}},

		// Add new record over container with no dataStorage map.
		{"3", cs2, args{"/proc/uptime", "uptime", "100"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.c.SetData(tt.args.path, tt.args.name, tt.args.data)
		})

		data, ok := tt.c.Data(tt.args.path, tt.args.name)
		if !ok {
			t.Errorf("Unexpected result during execution of testcase %v", tt.name)
		}

		assert.Equal(t, tt.args.data, data, "data fields are not matching")
	}
}

func Test_container_update(t *testing.T) {
	type fields struct {
		RWMutex       sync.RWMutex
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
		dataStore     domain.StateDataMap
		initProc      domain.ProcessIface
		service       domain.ContainerStateServiceIface
	}
	f1 := fields{}

	// Create local css as it's required by cntr.update() method.
	css := &containerStateService{
		idTable:     nil,
		usernsTable: nil,
		fss:         fss,
		prs:         prs,
		ios:         ios,
	}

	type args struct {
		src *container
	}
	a1 := args{
		src: &container{
			id:            "1",
			initPid:       1001,
			ctime:         time.Time{},
			uidFirst:      1,
			uidSize:       65535,
			gidFirst:      1,
			gidSize:       65535,
			procRoPaths:   nil,
			procMaskPaths: nil,
			specPaths:     make(map[string]struct{}),
			dataStore:     nil,
			initProc:      nil,
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
				RWMutex:       tt.fields.RWMutex,
				id:            tt.fields.id,
				initPid:       tt.fields.initPid,
				ctime:         tt.fields.ctime,
				uidFirst:      tt.fields.uidFirst,
				uidSize:       tt.fields.uidSize,
				gidFirst:      tt.fields.gidFirst,
				gidSize:       tt.fields.gidSize,
				procRoPaths:   tt.fields.procRoPaths,
				procMaskPaths: tt.fields.procMaskPaths,
				specPaths:     tt.fields.specPaths,
				dataStore:     tt.fields.dataStore,
				initProc:      tt.fields.initProc,
				service:       tt.fields.service,
			}

			if err := c.update(tt.args.src); (err != nil) != tt.wantErr {
				t.Errorf("container.update() error = %v, wantErr %v",
					err, tt.wantErr)
			}

			assert.Equal(t, c.initPid, tt.args.src.initPid)
			assert.Equal(t, c.ctime, tt.args.src.ctime)
			assert.NotEqual(t, c.initProc, tt.args.src.initProc)
			assert.Equal(t, c.uidFirst, tt.args.src.uidFirst)
			assert.Equal(t, c.uidSize, tt.args.src.uidSize)
			assert.Equal(t, c.gidFirst, tt.args.src.gidFirst)
			assert.Equal(t, c.gidSize, tt.args.src.gidSize)
		})
	}
}
