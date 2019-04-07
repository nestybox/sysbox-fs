package main

import (
	"reflect"
	"testing"

	"github.com/spf13/afero"
)

func Test_newPidContainerMap(t *testing.T) {

	type args struct {
		fs *sysvisorFS
	}

	tests := []struct {
		name string
		args args
		want *pidContainerMap
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := newPidContainerMap(tt.args.fs); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newPidContainerMap() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_pidContainerMap_get(t *testing.T) {
	type args struct {
		key uint64
	}
	tests := []struct {
		name  string
		pi    *pidContainerMap
		args  args
		want  *containerState
		want1 bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := tt.pi.get(tt.args.key)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("pidContainerMap.get() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("pidContainerMap.get() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func Test_pidContainerMap_set(t *testing.T) {
	type args struct {
		key   uint64
		value *containerState
	}
	tests := []struct {
		name string
		pi   *pidContainerMap
		args args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.pi.set(tt.args.key, tt.args.value)
		})
	}
}

func Test_pidContainerMap_delete(t *testing.T) {
	type args struct {
		key uint64
	}
	tests := []struct {
		name string
		pi   *pidContainerMap
		args args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.pi.delete(tt.args.key)
		})
	}
}

func Test_pidContainerMap_lookup(t *testing.T) {
	type args struct {
		key uint64
	}
	tests := []struct {
		name  string
		pi    *pidContainerMap
		args  args
		want  *containerState
		want1 bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := tt.pi.lookup(tt.args.key)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("pidContainerMap.lookup() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("pidContainerMap.lookup() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func Test_pidContainerMap_register(t *testing.T) {

	// Create proc entries in mem-based FS.
	afero.WriteFile(appFS, "/proc/101/ns/pid", []byte("100001"), 0644)
	afero.WriteFile(appFS, "/proc/303/ns/pid", []byte("300003"), 0644)

	// Testcase-global sysfs struct.
	var sysfs = &sysvisorFS{
		containerInodeMap: containerInodeMap{
			internal: map[string]uint64{
				"container3": 0,
			},
		},
	}

	// ContainerState 1
	var cs1 = &containerState{
		id:      "container1",
		initPid: 101,
	}
	// ContainerState 2
	var cs2 = &containerState{
		id:      "container2",
		initPid: 202,
	}
	// ContainerState 3
	var cs3 = &containerState{
		// Notice that this container-id overlaps with an existent entry in
		// containerInodeMap.
		id:      "container3",
		initPid: 303,
	}

	// PidNsInodeMap: Empty mapping table.
	var pidNsInodeContMap = &pidContainerMap{
		internal: make(map[uint64]*containerState),
		fs:       sysfs,
	}
	//sysfs.pidContainerMap.fs = sysfs

	type args struct {
		cs *containerState
	}
	tests := []struct {
		name    string
		pi      *pidContainerMap
		args    args
		wantErr bool
	}{
		// Register a new container with an existing "/proc/pid/ns" file.
		{"1", pidNsInodeContMap, args{cs1}, false},

		// Try to register an already-registered container (repeat 1.)
		// Error expected.
		{"2", pidNsInodeContMap, args{cs1}, true},

		// Register a new container with a non-existent "/proc/pid/ns" file.
		// Error expected.
		{"3", pidNsInodeContMap, args{cs2}, true},

		// Register a new container with a containerID matching an existent entry
		// in containerInodeMap. Error expected.
		{"4", pidNsInodeContMap, args{cs3}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.pi.register(tt.args.cs); (err != nil) != tt.wantErr {
				t.Errorf("pidContainerMap.register() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_pidContainerMap_unregister(t *testing.T) {

	// Create proc entries in mem-based FS.
	afero.WriteFile(appFS, "/proc/101/ns/pid", []byte("100001"), 0644)
	afero.WriteFile(appFS, "/proc/303/ns/pid", []byte("300003"), 0644)

	// Testcase-global sysfs struct.
	var sysfs = &sysvisorFS{
		containerInodeMap: containerInodeMap{
			internal: map[string]uint64{
				"container1": 100001,
				"container3": 300003,
			},
		},
		pidContainerMap: pidContainerMap{
			internal: make(map[uint64]*containerState),
		},
	}
	sysfs.pidContainerMap.fs = sysfs

	// ContainerState 1
	var cs1 = &containerState{
		id:         "container1",
		initPid:    101,
		pidNsInode: 100001,
	}
	// ContainerState 2
	var cs2 = &containerState{
		id:      "container2",
		initPid: 202,
	}
	// ContainerState 3
	var cs3 = &containerState{
		// Notice that this container-id overlaps with an existent entry in
		// containerInodeMap.
		id:      "container3",
		initPid: 303,
	}

	// Inserting cs1 into global pidContainerMap. Notice that this cannot
	// be done during the initialization of sysfs above, as pidContainerMap
	// struct requires a pointer to sysfs variable, and this recursive referal
	// is not permitted by Go.
	sysfs.pidContainerMap.set(cs1.pidNsInode, cs1)

	type args struct {
		cs *containerState
	}
	tests := []struct {
		name    string
		pi      *pidContainerMap
		args    args
		wantErr bool
	}{
		// Unregister a container with an existing "/proc/pid/ns" file.
		{"1", &sysfs.pidContainerMap, args{cs1}, false},

		// Repeat 1. Error expected as container is already unregister.
		{"2", &sysfs.pidContainerMap, args{cs1}, true},

		// Try to unregister a container with no matching entry in containerIDMap.
		// Error expected.
		{"3", &sysfs.pidContainerMap, args{cs2}, true},

		// Try to unregister a container with no matching entry in pidContainerMap.
		// Error expected.
		{"4", &sysfs.pidContainerMap, args{cs3}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.pi.unregister(tt.args.cs); (err != nil) != tt.wantErr {
				t.Errorf("pidContainerMap.unregister() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_pidContainerMap_update(t *testing.T) {

	// Create proc entries in mem-based FS.
	afero.WriteFile(appFS, "/proc/101/ns/pid", []byte("100001"), 0644)
	afero.WriteFile(appFS, "/proc/303/ns/pid", []byte("300003"), 0644)

	// Testcase-global sysfs struct.
	var sysfs = &sysvisorFS{
		containerInodeMap: containerInodeMap{
			internal: map[string]uint64{
				"container1": 100001,
				"container3": 300003,
			},
		},
		pidContainerMap: pidContainerMap{
			internal: make(map[uint64]*containerState),
		},
	}
	sysfs.pidContainerMap.fs = sysfs

	// ContainerState 1
	var cs1 = &containerState{
		id:         "container1",
		initPid:    101,
		pidNsInode: 100001,
	}
	// ContainerState 2
	var cs2 = &containerState{
		id:      "container2",
		initPid: 202,
	}
	// ContainerState 3
	var cs3 = &containerState{
		// Notice that this container-id overlaps with an existent entry in
		// containerInodeMap.
		id:      "container3",
		initPid: 303,
	}

	// Inserting cs1 into global pidContainerMap. Notice that this cannot
	// be done during the initialization of sysfs above, as pidContainerMap
	// struct requires a pointer to sysfs variable, and this recursive referal
	// is not permitted by Go.
	sysfs.pidContainerMap.set(cs1.pidNsInode, cs1)

	type args struct {
		cs *containerState
	}
	tests := []struct {
		name    string
		pi      *pidContainerMap
		args    args
		wantErr bool
	}{
		// Update a container with an existing "/proc/pid/ns" file.
		{"1", &sysfs.pidContainerMap, args{cs1}, false},

		// Repeat 1. We are updating here, so no error is expected.
		{"2", &sysfs.pidContainerMap, args{cs1}, false},

		// Try to update a container with no matching entry in containerIDMap.
		// Error expected.
		{"3", &sysfs.pidContainerMap, args{cs2}, true},

		// Try to update a container with no matching entry in pidContainerMap.
		// Error expected.
		{"4", &sysfs.pidContainerMap, args{cs3}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.pi.update(tt.args.cs); (err != nil) != tt.wantErr {
				t.Errorf("pidContainerMap.update() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_pidContainerMap_pidInodeRegistered(t *testing.T) {

	// Create a mem-based FS.
	afero.WriteFile(appFS, "/proc/101/ns/pid", []byte("100001"), 0644)
	afero.WriteFile(appFS, "/proc/303/ns/pid", []byte("300003"), 0644)

	// ContainerState 1
	var cs1 = &containerState{
		id:         "container1",
		initPid:    101,
		pidNsInode: 100001,
	}

	// PidNsInodeMap: Empty mapping table.
	var pidNsInodeContMap = &pidContainerMap{
		internal: map[uint64]*containerState{
			100001: cs1,
		},
	}

	type args struct {
		pid uint32
	}
	tests := []struct {
		name string
		pi   *pidContainerMap
		args args
		want bool
	}{
		// Asking for a container-registration with a pidInode matching an existing
		// proc/pid entry.
		{"1", pidNsInodeContMap, args{101}, true},

		// Asking for a container-registration with a pidInode matching a non-existent
		// proc/pid entry.
		{"2", pidNsInodeContMap, args{202}, false},

		// Asking for a container-registration with a pidInode matching an existing
		// proc/pid entry, BUT with no associated entry in the pidContainerMap.
		{"2", pidNsInodeContMap, args{303}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.pi.pidRegistered(tt.args.pid); got != tt.want {
				t.Errorf("pidContainerMap.pidInodeRegistered() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_findInodeByPid(t *testing.T) {

	// Create a mem-based FS.
	afero.WriteFile(appFS, "/proc/123/ns/pid", []byte("123456"), 0644)

	type args struct {
		pid uint32
	}
	tests := []struct {
		name    string
		args    args
		want    uint64
		wantErr bool
	}{
		// Requesting inode for a pid with a matching /proc/pid file.
		{"1", args{123}, 123456, false},

		// Requesting inode for a pid with a matching /proc/pid file. Error
		// expected.
		{"2", args{1234}, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := findInodeByPid(tt.args.pid)
			if (err != nil) != tt.wantErr {
				t.Errorf("findInodeByPid() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("findInodeByPid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_findContainerByPid(t *testing.T) {

	// Create a mem-based FS.
	afero.WriteFile(appFS, "/proc/101/ns/pid", []byte("100001"), 0644)
	afero.WriteFile(appFS, "/proc/303/ns/pid", []byte("300003"), 0644)

	// Testcase-global sysfs struct.
	sysfs = &sysvisorFS{
		pidContainerMap: pidContainerMap{
			internal: make(map[uint64]*containerState),
		},
	}
	sysfs.pidContainerMap.fs = sysfs

	// ContainerState 1
	var cs1 = &containerState{
		id:         "container1",
		initPid:    101,
		pidNsInode: 100001,
	}

	// Inserting cs1 into global pidContainerMap.
	sysfs.pidContainerMap.set(cs1.pidNsInode, cs1)

	type args struct {
		pid uint32
	}
	tests := []struct {
		name    string
		args    args
		want    *containerState
		wantErr bool
	}{
		// Asking for container with an existing /proc/pid entry.
		{"1", args{101}, cs1, false},

		// Asking for a container with a non-existent /proc/pid entry. Error
		// expected.
		{"2", args{202}, nil, true},

		// Asking for a container with a valid /prox/pid entry but with a
		// non-existent pidInode in the pidContainerMap. Error expected.
		{"3", args{303}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := findContainerByPid(tt.args.pid)
			if (err != nil) != tt.wantErr {
				t.Errorf("findContainerByPid() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("findContainerByPid() = %v, want %v", got, tt.want)
			}
		})
	}
}
