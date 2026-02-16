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

// Package pidfd provides pidfd_open, pidfd_getfd, pidfd_send_signal support on linux 5.6+.
//
// pidfd_send_signal() --> kernel 5.1+
// pidfd_open()        --> kernel 5.3+
// pidfd_getfd()       --> kernel 5.6+
//
// Sysbox is currently only using pidfd_open().

package pidfd

import "syscall"

const (
	sys_pidfd_send_signal = 424
	sys_pidfd_open        = 434
	sys_pidfd_getfd       = 438
)

// PidFd, a file descriptor that refers to a process.
type PidFd int

// Open obtains a file descriptor that refers to a process.
//
// The flags argument is reserved for future use; currently, this argument must be specified as 0.
func Open(pid int, flags uint) (PidFd, error) {
	fd, _, errno := syscall.Syscall(sys_pidfd_open, uintptr(pid), uintptr(flags), 0)
	if errno != 0 {
		return 0, errno
	}

	return PidFd(fd), nil
}

// GetFd obtain a duplicate of another process's file descriptor.
//
// The flags argument is reserved for future use; currently, this argument must be specified as 0.
func (fd PidFd) GetFd(targetfd int, flags uint) (int, error) {
	newfd, _, errno := syscall.Syscall(sys_pidfd_getfd, uintptr(fd), uintptr(targetfd), uintptr(flags))

	if errno != 0 {
		return 0, errno
	}

	return int(newfd), nil
}

// SendSignal send a signal to a process specified by a PidFd.
//
// The flags argument is reserved for future use; currently, this argument must be specified as 0.
func (fd PidFd) SendSignal(signal syscall.Signal, flags uint) error {
	_, _, errno := syscall.Syscall6(sys_pidfd_send_signal, uintptr(fd), uintptr(signal), 0, uintptr(flags), 0, 0)

	if errno != 0 {
		return errno
	}

	return nil
}
