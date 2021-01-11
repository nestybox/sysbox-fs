// Code generated by mockery v1.0.0. DO NOT EDIT.

package mocks

import (
	domain "github.com/nestybox/sysbox-fs/domain"
	mock "github.com/stretchr/testify/mock"

	time "time"
)

// ContainerIface is an autogenerated mock type for the ContainerIface type
type ContainerIface struct {
	mock.Mock
}

// Ctime provides a mock function with given fields:
func (_m *ContainerIface) Ctime() time.Time {
	ret := _m.Called()

	var r0 time.Time
	if rf, ok := ret.Get(0).(func() time.Time); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(time.Time)
	}

	return r0
}

// Data provides a mock function with given fields: path, name
func (_m *ContainerIface) Data(path string, name string) (string, bool) {
	ret := _m.Called(path, name)

	var r0 string
	if rf, ok := ret.Get(0).(func(string, string) string); ok {
		r0 = rf(path, name)
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 bool
	if rf, ok := ret.Get(1).(func(string, string) bool); ok {
		r1 = rf(path, name)
	} else {
		r1 = ret.Get(1).(bool)
	}

	return r0, r1
}

// GID provides a mock function with given fields:
func (_m *ContainerIface) GID() uint32 {
	ret := _m.Called()

	var r0 uint32
	if rf, ok := ret.Get(0).(func() uint32); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(uint32)
	}

	return r0
}

// ID provides a mock function with given fields:
func (_m *ContainerIface) ID() string {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// InitPid provides a mock function with given fields:
func (_m *ContainerIface) InitPid() uint32 {
	ret := _m.Called()

	var r0 uint32
	if rf, ok := ret.Get(0).(func() uint32); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(uint32)
	}

	return r0
}

// InitProc provides a mock function with given fields:
func (_m *ContainerIface) InitProc() domain.ProcessIface {
	ret := _m.Called()

	var r0 domain.ProcessIface
	if rf, ok := ret.Get(0).(func() domain.ProcessIface); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(domain.ProcessIface)
		}
	}

	return r0
}

// IsImmutableBindMount provides a mock function with given fields: info
func (_m *ContainerIface) IsImmutableBindMount(info *domain.MountInfo) bool {
	ret := _m.Called(info)

	var r0 bool
	if rf, ok := ret.Get(0).(func(*domain.MountInfo) bool); ok {
		r0 = rf(info)
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// IsImmutableMountID provides a mock function with given fields: id
func (_m *ContainerIface) IsImmutableMountID(id int) bool {
	ret := _m.Called(id)

	var r0 bool
	if rf, ok := ret.Get(0).(func(int) bool); ok {
		r0 = rf(id)
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// IsImmutableMountpoint provides a mock function with given fields: mp
func (_m *ContainerIface) IsImmutableMountpoint(mp string) bool {
	ret := _m.Called(mp)

	var r0 bool
	if rf, ok := ret.Get(0).(func(string) bool); ok {
		r0 = rf(mp)
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// IsImmutableRoBindMount provides a mock function with given fields: info
func (_m *ContainerIface) IsImmutableRoBindMount(info *domain.MountInfo) bool {
	ret := _m.Called(info)

	var r0 bool
	if rf, ok := ret.Get(0).(func(*domain.MountInfo) bool); ok {
		r0 = rf(info)
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// IsImmutableRoMountID provides a mock function with given fields: id
func (_m *ContainerIface) IsImmutableRoMountID(id int) bool {
	ret := _m.Called(id)

	var r0 bool
	if rf, ok := ret.Get(0).(func(int) bool); ok {
		r0 = rf(id)
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// Lock provides a mock function with given fields:
func (_m *ContainerIface) Lock() {
	_m.Called()
}

// ProcMaskPaths provides a mock function with given fields:
func (_m *ContainerIface) ProcMaskPaths() []string {
	ret := _m.Called()

	var r0 []string
	if rf, ok := ret.Get(0).(func() []string); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	return r0
}

// ProcRoPaths provides a mock function with given fields:
func (_m *ContainerIface) ProcRoPaths() []string {
	ret := _m.Called()

	var r0 []string
	if rf, ok := ret.Get(0).(func() []string); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	return r0
}

// SetData provides a mock function with given fields: path, name, data
func (_m *ContainerIface) SetData(path string, name string, data string) {
	_m.Called(path, name, data)
}

// SetInitProc provides a mock function with given fields: pid, uid, gid
func (_m *ContainerIface) SetInitProc(pid uint32, uid uint32, gid uint32) error {
	ret := _m.Called(pid, uid, gid)

	var r0 error
	if rf, ok := ret.Get(0).(func(uint32, uint32, uint32) error); ok {
		r0 = rf(pid, uid, gid)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// String provides a mock function with given fields:
func (_m *ContainerIface) String() string {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// UID provides a mock function with given fields:
func (_m *ContainerIface) UID() uint32 {
	ret := _m.Called()

	var r0 uint32
	if rf, ok := ret.Get(0).(func() uint32); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(uint32)
	}

	return r0
}

// Unlock provides a mock function with given fields:
func (_m *ContainerIface) Unlock() {
	_m.Called()
}
