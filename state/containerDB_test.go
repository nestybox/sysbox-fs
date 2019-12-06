//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

package state

import (
	"reflect"
	"testing"
	"time"

	"github.com/nestybox/sysbox-fs/domain"
)

func TestNewContainerStateService(t *testing.T) {

	var expectedResult = &containerStateService{}

	tests := []struct {
		name string
		want domain.ContainerStateService
	}{
		{"1", expectedResult},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewContainerStateService()
			if !reflect.DeepEqual(got, tt.want) {
				//t.Errorf("NewContainerStateService() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_containerStateService_ContainerCreate(t *testing.T) {
	type args struct {
		id       string
		initpid  uint32
		hostname string
		inode    domain.Inode
		ctime    time.Time
		uidFirst uint32
		uidSize  uint32
		gidFirst uint32
		gidSize  uint32
	}

	var css *containerStateService

	var cs = &container{
		id:       "1",
		initPid:  1001,
		hostname: "syscont",
		pidInode: 123456,
		ctime:    time.Time{},
		uidFirst: 1,
		uidSize:  65535,
		gidFirst: 1,
		gidSize:  65535,
	}

	tests := []struct {
		name string
		css  *containerStateService
		args args
		want domain.ContainerIface
	}{
		// Create a new container and verify that it fully match the arguments
		// originally passed.
		{"1", css, args{
			cs.id,
			cs.initPid,
			cs.hostname,
			cs.pidInode,
			cs.ctime,
			cs.uidFirst,
			cs.uidSize,
			cs.gidFirst,
			cs.gidSize,
		}, cs},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.css.ContainerCreate(
				tt.args.id,
				tt.args.initpid,
				tt.args.hostname,
				tt.args.inode,
				tt.args.ctime,
				tt.args.uidFirst,
				tt.args.uidSize,
				tt.args.gidFirst,
				tt.args.gidSize); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("containerStateService.ContainerCreate() = %v, want %v",
					got, tt.want)
			}
		})
	}
}

func Test_containerStateService_ContainerAdd(t *testing.T) {
	type args struct {
		c domain.ContainerIface
	}

	var cs1 = &container{
		id:       "cs1",
		pidInode: 1111111,
	}

	var cs2 = &container{
		id: "cs2",
	}

	var cs3 = &container{
		id:       "cs3",
		pidInode: 333333,
	}

	var css = &containerStateService{
		idTable: map[string]domain.Inode{
			"cs2": 222222,
		},
		pidTable: map[domain.Inode]*container{
			222222: cs2,
			333333: cs3,
		},
	}

	tests := []struct {
		name    string
		css     *containerStateService
		args    args
		wantErr bool
	}{
		// Register a new/non-existing container.
		{"1", css, args{cs1}, false},

		// Register an already-present container (with matching container ID).
		// Error expected.
		{"2", css, args{cs2}, true},

		// Register an already-present container (with matching container
		// pidNsInode). Error expected.
		{"3", css, args{cs3}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.css.ContainerAdd(tt.args.c); (err != nil) != tt.wantErr {
				t.Errorf("containerStateService.ContainerAdd() error = %v, wantErr %v",
					err, tt.wantErr)
			}

			// Verify that containers were properly added.
			if cntr := tt.css.ContainerLookupById(tt.args.c.ID()); cntr == nil {
				if !tt.wantErr {
					t.Errorf("Unexpected result during execution of testcase %v", tt.name)
				}
			}
		})
	}
}

func Test_containerStateService_ContainerUpdate(t *testing.T) {
	type args struct {
		c domain.ContainerIface
	}

	var cs1 = &container{
		id:       "cs1",
		pidInode: 1111111,
	}

	var cs2 = &container{
		id: "cs2",
	}

	var cs3 = &container{
		id:       "cs3",
		pidInode: 333333,
	}

	var css = &containerStateService{
		idTable: map[string]domain.Inode{
			"cs1": 111111,
			"cs3": 333333,
		},
		pidTable: map[domain.Inode]*container{
			111111: cs1,
			222222: cs2,
		},
	}

	tests := []struct {
		name    string
		css     *containerStateService
		args    args
		wantErr bool
	}{
		// Update a valid/existing container.
		{"1", css, args{cs1}, false},

		// Update a container whose container-ID is not present in the idTable.
		// Error expected.
		{"2", css, args{cs2}, true},

		// Update a container whose podNsInode is not present in the pidTable.
		// Error expected.
		{"3", css, args{cs3}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.css.ContainerUpdate(tt.args.c); (err != nil) != tt.wantErr {
				t.Errorf("containerStateService.ContainerUpdate() error = %v, wantErr %v",
					err, tt.wantErr)
			}
		})
	}
}

func Test_containerStateService_ContainerDelete(t *testing.T) {
	type args struct {
		c domain.ContainerIface
	}

	var cs1 = &container{
		id:       "cs1",
		pidInode: 1111111,
	}

	var cs2 = &container{
		id: "cs2",
	}

	var cs3 = &container{
		id:       "cs3",
		pidInode: 333333,
	}

	var css = &containerStateService{
		idTable: map[string]domain.Inode{
			"cs1": 111111,
			"cs3": 333333,
		},
		pidTable: map[domain.Inode]*container{
			111111: cs1,
			222222: cs2,
		},
	}

	tests := []struct {
		name    string
		css     *containerStateService
		args    args
		wantErr bool
	}{
		// Delete a valid/existing container.
		{"1", css, args{cs1}, false},

		// Delete a container with invalid/missing ID. Error expected.
		{"2", css, args{cs2}, true},

		// Delete a container with invalid/missing pidNsInode. Error expected.
		{"3", css, args{cs3}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.css.ContainerDelete(tt.args.c); (err != nil) != tt.wantErr {
				t.Errorf("containerStateService.ContainerDelete() error = %v, wantErr %v",
					err, tt.wantErr)
			}

			// Verify that containers are properly deleted.
			if cntr := tt.css.ContainerLookupById(tt.args.c.ID()); cntr != nil {
				t.Errorf("Unexpected result during execution of testcase %v", tt.name)
			}
		})
	}
}

func Test_containerStateService_ContainerLookupById(t *testing.T) {
	type args struct {
		id string
	}

	var cs1 = &container{
		id:       "cs1",
		pidInode: 1111111,
	}

	var cs2 = &container{
		id: "cs2",
	}

	var css = &containerStateService{
		idTable: map[string]domain.Inode{
			"cs1": 111111,
			"cs3": 333333,
		},
		pidTable: map[domain.Inode]*container{
			111111: cs1,
			222222: cs2,
		},
	}

	tests := []struct {
		name string
		css  *containerStateService
		args args
		want domain.ContainerIface
	}{
		// Lookup a valid/existing container.
		{"1", css, args{"cs1"}, cs1},

		// Lookup a container with no matching entry in the idTable.
		// Error expected.
		{"2", css, args{"cs2"}, nil},

		// Lookup a container with no matching entry in the pidTable.
		// Error expected.
		{"3", css, args{"cs3"}, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.css.ContainerLookupById(tt.args.id); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("containerStateService.ContainerLookupById() = %v, want %v",
					got, tt.want)
			}
		})
	}
}

func Test_containerStateService_ContainerLookupByInode(t *testing.T) {
	type args struct {
		pidInode domain.Inode
	}

	var cs1 = &container{
		id:       "cs1",
		pidInode: 1111111,
	}

	var cs2 = &container{
		id: "cs2",
	}

	var css = &containerStateService{
		idTable: map[string]domain.Inode{
			"cs1": 111111,
			"cs3": 333333,
		},
		pidTable: map[domain.Inode]*container{
			111111: cs1,
			222222: cs2,
		},
	}

	tests := []struct {
		name string
		css  *containerStateService
		args args
		want domain.ContainerIface
	}{
		// Lookup a valid/existing container.
		{"1", css, args{111111}, cs1},

		// Lookup a container with no matching entry in the pidTable.
		// Error expected.
		{"2", css, args{222222}, nil},

		// Lookup a container with no matching entry in the pidTable.
		// Error expected.
		{"3", css, args{333333}, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.css.ContainerLookupByInode(tt.args.pidInode); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("containerStateService.ContainerLookupByInode() = %v, want %v",
					got, tt.want)
			}
		})
	}
}
