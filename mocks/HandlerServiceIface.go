// Code generated by mockery v1.0.0. DO NOT EDIT.

package mocks

import (
	domain "github.com/nestybox/sysbox-fs/domain"
	mock "github.com/stretchr/testify/mock"
)

// HandlerServiceIface is an autogenerated mock type for the HandlerServiceIface type
type HandlerServiceIface struct {
	mock.Mock
}

// DisableHandler provides a mock function with given fields: path
func (_m *HandlerServiceIface) DisableHandler(path string) error {
	ret := _m.Called(path)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(path)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// EnableHandler provides a mock function with given fields: path
func (_m *HandlerServiceIface) EnableHandler(path string) error {
	ret := _m.Called(path)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(path)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// FindHandler provides a mock function with given fields: s
func (_m *HandlerServiceIface) FindHandler(s string) (domain.HandlerIface, bool) {
	ret := _m.Called(s)

	var r0 domain.HandlerIface
	if rf, ok := ret.Get(0).(func(string) domain.HandlerIface); ok {
		r0 = rf(s)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(domain.HandlerIface)
		}
	}

	var r1 bool
	if rf, ok := ret.Get(1).(func(string) bool); ok {
		r1 = rf(s)
	} else {
		r1 = ret.Get(1).(bool)
	}

	return r0, r1
}

// FindHostUuid provides a mock function with given fields:
func (_m *HandlerServiceIface) FindHostUuid() (string, error) {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FindUserNsInode provides a mock function with given fields: pid
func (_m *HandlerServiceIface) FindUserNsInode(pid uint32) (uint64, error) {
	ret := _m.Called(pid)

	var r0 uint64
	if rf, ok := ret.Get(0).(func(uint32) uint64); ok {
		r0 = rf(pid)
	} else {
		r0 = ret.Get(0).(uint64)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(uint32) error); ok {
		r1 = rf(pid)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetPassThroughHandler provides a mock function with given fields:
func (_m *HandlerServiceIface) GetPassThroughHandler() domain.HandlerIface {
	ret := _m.Called()

	var r0 domain.HandlerIface
	if rf, ok := ret.Get(0).(func() domain.HandlerIface); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(domain.HandlerIface)
		}
	}

	return r0
}

// HandlersResourcesList provides a mock function with given fields:
func (_m *HandlerServiceIface) HandlersResourcesList() []string {
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

// HostUserNsInode provides a mock function with given fields:
func (_m *HandlerServiceIface) HostUserNsInode() uint64 {
	ret := _m.Called()

	var r0 uint64
	if rf, ok := ret.Get(0).(func() uint64); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(uint64)
	}

	return r0
}

// HostUuid provides a mock function with given fields:
func (_m *HandlerServiceIface) HostUuid() string {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// IOService provides a mock function with given fields:
func (_m *HandlerServiceIface) IOService() domain.IOServiceIface {
	ret := _m.Called()

	var r0 domain.IOServiceIface
	if rf, ok := ret.Get(0).(func() domain.IOServiceIface); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(domain.IOServiceIface)
		}
	}

	return r0
}

// IgnoreErrors provides a mock function with given fields:
func (_m *HandlerServiceIface) IgnoreErrors() bool {
	ret := _m.Called()

	var r0 bool
	if rf, ok := ret.Get(0).(func() bool); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// LookupHandler provides a mock function with given fields: i
func (_m *HandlerServiceIface) LookupHandler(i domain.IOnodeIface) (domain.HandlerIface, bool) {
	ret := _m.Called(i)

	var r0 domain.HandlerIface
	if rf, ok := ret.Get(0).(func(domain.IOnodeIface) domain.HandlerIface); ok {
		r0 = rf(i)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(domain.HandlerIface)
		}
	}

	var r1 bool
	if rf, ok := ret.Get(1).(func(domain.IOnodeIface) bool); ok {
		r1 = rf(i)
	} else {
		r1 = ret.Get(1).(bool)
	}

	return r0, r1
}

// NSenterService provides a mock function with given fields:
func (_m *HandlerServiceIface) NSenterService() domain.NSenterServiceIface {
	ret := _m.Called()

	var r0 domain.NSenterServiceIface
	if rf, ok := ret.Get(0).(func() domain.NSenterServiceIface); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(domain.NSenterServiceIface)
		}
	}

	return r0
}

// ProcessService provides a mock function with given fields:
func (_m *HandlerServiceIface) ProcessService() domain.ProcessServiceIface {
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

// RegisterHandler provides a mock function with given fields: h
func (_m *HandlerServiceIface) RegisterHandler(h domain.HandlerIface) error {
	ret := _m.Called(h)

	var r0 error
	if rf, ok := ret.Get(0).(func(domain.HandlerIface) error); ok {
		r0 = rf(h)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// SetStateService provides a mock function with given fields: css
func (_m *HandlerServiceIface) SetStateService(css domain.ContainerStateServiceIface) {
	_m.Called(css)
}

// Setup provides a mock function with given fields: hdlrs, ignoreErrors, css, nss, prs, ios
func (_m *HandlerServiceIface) Setup(hdlrs []domain.HandlerIface, ignoreErrors bool, css domain.ContainerStateServiceIface, nss domain.NSenterServiceIface, prs domain.ProcessServiceIface, ios domain.IOServiceIface) {
	_m.Called(hdlrs, ignoreErrors, css, nss, prs, ios)
}

// StateService provides a mock function with given fields:
func (_m *HandlerServiceIface) StateService() domain.ContainerStateServiceIface {
	ret := _m.Called()

	var r0 domain.ContainerStateServiceIface
	if rf, ok := ret.Get(0).(func() domain.ContainerStateServiceIface); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(domain.ContainerStateServiceIface)
		}
	}

	return r0
}

// UnregisterHandler provides a mock function with given fields: h
func (_m *HandlerServiceIface) UnregisterHandler(h domain.HandlerIface) error {
	ret := _m.Called(h)

	var r0 error
	if rf, ok := ret.Get(0).(func(domain.HandlerIface) error); ok {
		r0 = rf(h)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}
