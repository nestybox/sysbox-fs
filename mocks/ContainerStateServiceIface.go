// Code generated by mockery v1.0.0. DO NOT EDIT.

package mocks

import (
	domain "github.com/nestybox/sysbox-fs/domain"
	mock "github.com/stretchr/testify/mock"

	time "time"
)

// ContainerStateServiceIface is an autogenerated mock type for the ContainerStateServiceIface type
type ContainerStateServiceIface struct {
	mock.Mock
}

// ContainerCreate provides a mock function with given fields: id, pid, ctime, uidFirst, uidSize, gidFirst, gidSize, procRoPaths, procMaskPaths, service
func (_m *ContainerStateServiceIface) ContainerCreate(id string, pid uint32, ctime time.Time, uidFirst uint32, uidSize uint32, gidFirst uint32, gidSize uint32, procRoPaths []string, procMaskPaths []string, service domain.ContainerStateServiceIface) domain.ContainerIface {
	ret := _m.Called(id, pid, ctime, uidFirst, uidSize, gidFirst, gidSize, procRoPaths, procMaskPaths, service)

	var r0 domain.ContainerIface
	if rf, ok := ret.Get(0).(func(string, uint32, time.Time, uint32, uint32, uint32, uint32, []string, []string, domain.ContainerStateServiceIface) domain.ContainerIface); ok {
		r0 = rf(id, pid, ctime, uidFirst, uidSize, gidFirst, gidSize, procRoPaths, procMaskPaths, service)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(domain.ContainerIface)
		}
	}

	return r0
}

// ContainerDBSize provides a mock function with given fields:
func (_m *ContainerStateServiceIface) ContainerDBSize() int {
	ret := _m.Called()

	var r0 int
	if rf, ok := ret.Get(0).(func() int); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(int)
	}

	return r0
}

// ContainerLookupById provides a mock function with given fields: id
func (_m *ContainerStateServiceIface) ContainerLookupById(id string) domain.ContainerIface {
	ret := _m.Called(id)

	var r0 domain.ContainerIface
	if rf, ok := ret.Get(0).(func(string) domain.ContainerIface); ok {
		r0 = rf(id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(domain.ContainerIface)
		}
	}

	return r0
}

// ContainerLookupByInode provides a mock function with given fields: usernsInode
func (_m *ContainerStateServiceIface) ContainerLookupByInode(usernsInode uint64) domain.ContainerIface {
	ret := _m.Called(usernsInode)

	var r0 domain.ContainerIface
	if rf, ok := ret.Get(0).(func(uint64) domain.ContainerIface); ok {
		r0 = rf(usernsInode)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(domain.ContainerIface)
		}
	}

	return r0
}

// ContainerPreRegister provides a mock function with given fields: id, userns
func (_m *ContainerStateServiceIface) ContainerPreRegister(id, userns string) error {
	ret := _m.Called(id)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ContainerRegister provides a mock function with given fields: c
func (_m *ContainerStateServiceIface) ContainerRegister(c domain.ContainerIface) error {
	ret := _m.Called(c)

	var r0 error
	if rf, ok := ret.Get(0).(func(domain.ContainerIface) error); ok {
		r0 = rf(c)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ContainerUnregister provides a mock function with given fields: c
func (_m *ContainerStateServiceIface) ContainerUnregister(c domain.ContainerIface) error {
	ret := _m.Called(c)

	var r0 error
	if rf, ok := ret.Get(0).(func(domain.ContainerIface) error); ok {
		r0 = rf(c)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ContainerUpdate provides a mock function with given fields: c
func (_m *ContainerStateServiceIface) ContainerUpdate(c domain.ContainerIface) error {
	ret := _m.Called(c)

	var r0 error
	if rf, ok := ret.Get(0).(func(domain.ContainerIface) error); ok {
		r0 = rf(c)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// FuseServerService provides a mock function with given fields:
func (_m *ContainerStateServiceIface) FuseServerService() domain.FuseServerServiceIface {
	ret := _m.Called()

	var r0 domain.FuseServerServiceIface
	if rf, ok := ret.Get(0).(func() domain.FuseServerServiceIface); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(domain.FuseServerServiceIface)
		}
	}

	return r0
}

// MountService provides a mock function with given fields:
func (_m *ContainerStateServiceIface) MountService() domain.MountServiceIface {
	ret := _m.Called()

	var r0 domain.MountServiceIface
	if rf, ok := ret.Get(0).(func() domain.MountServiceIface); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(domain.MountServiceIface)
		}
	}

	return r0
}

// ProcessService provides a mock function with given fields:
func (_m *ContainerStateServiceIface) ProcessService() domain.ProcessServiceIface {
	ret := _m.Called()

	var r0 domain.ProcessServiceIface
	if rf, ok := ret.Get(0).(func() domain.ProcessServiceIface); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(domain.ProcessServiceIface)
		}
	}

	return r0
}

// Setup provides a mock function with given fields: fss, prs, ios, mts
func (_m *ContainerStateServiceIface) Setup(fss domain.FuseServerServiceIface, prs domain.ProcessServiceIface, ios domain.IOServiceIface, mts domain.MountServiceIface) {
	_m.Called(fss, prs, ios, mts)
}
