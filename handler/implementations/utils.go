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

package implementations

import (
	"errors"
	"io"
	"math/rand"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
	"github.com/sirupsen/logrus"
)

const (
	MaxInt = int(^uint(0) >> 1)
	MinInt = -MaxInt - 1
)

func readFileInt(
	h domain.HandlerIface,
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	name := n.Name()
	path := n.Path()
	cntr := req.Container

	// Ensure operation is generated from within a registered sys container.
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return 0, errors.New("Container not found")
	}

	cntr.Lock()

	// Check if this resource has been initialized for this container. Otherwise,
	// fetch the information from the host FS and store it accordingly within
	// the container struct.
	data, ok := cntr.Data(path, name)
	if !ok {
		val, err := fetchFileData(h, n, cntr)
		if err != nil && err != io.EOF {
			cntr.Unlock()
			return 0, err
		}

		// High-level verification to ensure that format is the expected one.
		_, err = strconv.Atoi(val)
		if err != nil {
			logrus.Errorf("Unexpected content read from file %v, error %v",
				n.Path(), err)
			return 0, err
		}

		cntr.SetData(path, name, val)
		data = val
	}

	cntr.Unlock()

	data += "\n"

	return copyResultBuffer(req.Data, []byte(data))
}

func readFileString(
	h domain.HandlerIface,
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	name := n.Name()
	path := n.Path()
	cntr := req.Container

	cntr.Lock()

	// Check if this resource has been initialized for this container. Otherwise,
	// fetch the information from the host FS and store it accordingly within
	// the container struct.
	data, ok := cntr.Data(path, name)
	if !ok {
		val, err := fetchFileData(h, n, cntr)
		if err != nil && err != io.EOF {
			cntr.Unlock()
			return 0, err
		}

		cntr.SetData(path, name, data)
		data = val
	}

	cntr.Unlock()

	data += "\n"

	return copyResultBuffer(req.Data, []byte(data))
}

func fetchFileData(
	h domain.HandlerIface,
	n domain.IOnodeIface,
	c domain.ContainerIface) (string, error) {

	// We need the per-resource lock since we are about to access the resource on
	// the host FS. See pushFile() for a full explanation.
	hmux := h.GetMutex()
	hmux.Lock()

	// Read from host FS to extract the existing value.
	data, err := n.ReadLine()
	if err != nil && err != io.EOF {
		hmux.Unlock()
		logrus.Errorf("Could not read from file %v", n.Path())
		return "", err
	}

	hmux.Unlock()

	return data, nil
}

func writeMaxInt(
	h domain.HandlerIface,
	n domain.IOnodeIface,
	req *domain.HandlerRequest,
	kernelSync bool) (int, error) {

	name := n.Name()
	path := n.Path()
	cntr := req.Container

	newMax := strings.TrimSpace(string(req.Data))
	newMaxInt, err := strconv.Atoi(newMax)
	if err != nil {
		logrus.Errorf("Unexpected error: %v", err)
		return 0, err
	}

	// Ensure operation is generated from within a registered sys container.
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return 0, errors.New("Container not found")
	}

	cntr.Lock()
	defer cntr.Unlock()

	// Check if this resource has been initialized for this container. If not,
	// push it to the host FS and store it within the container struct.
	curMax, ok := cntr.Data(path, name)
	if !ok {
		if kernelSync {
			if err := pushFileMaxInt(h, n, cntr, newMaxInt); err != nil {
				return 0, err
			}
		}

		cntr.SetData(path, name, newMax)

		return len(req.Data), nil
	}

	curMaxInt, err := strconv.Atoi(curMax)
	if err != nil {
		logrus.Errorf("Unexpected error: %v", err)
		return 0, err
	}

	// If new value is lower than the existing one, then let's update this
	// new value into the container struct but not push it down to the kernel.
	if newMaxInt < curMaxInt {
		cntr.SetData(path, name, newMax)

		return len(req.Data), nil
	}

	// Push new value to the kernel.
	if kernelSync {
		if err := pushFileMaxInt(h, n, cntr, newMaxInt); err != nil {
			return 0, io.EOF
		}
	}

	// Writing the new value into container-state struct.
	cntr.SetData(path, name, newMax)

	return len(req.Data), nil
}

func writeMinInt(
	h domain.HandlerIface,
	n domain.IOnodeIface,
	req *domain.HandlerRequest,
	kernelSync bool) (int, error) {

	name := n.Name()
	path := n.Path()
	cntr := req.Container

	newMin := strings.TrimSpace(string(req.Data))
	newMinInt, err := strconv.Atoi(newMin)
	if err != nil {
		logrus.Errorf("Unexpected error: %v", err)
		return 0, err
	}

	// Ensure operation is generated from within a registered sys container.
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return 0, errors.New("Container not found")
	}

	cntr.Lock()
	defer cntr.Unlock()

	// Check if this resource has been initialized for this container. If not,
	// push it down to the kernel and store it within the container struct.
	curMax, ok := cntr.Data(path, name)
	if !ok {
		if kernelSync {
			if err := pushFileMinInt(h, n, cntr, newMinInt); err != nil {
				return 0, err
			}
		}

		cntr.SetData(path, name, newMin)

		return len(req.Data), nil
	}

	curMinInt, err := strconv.Atoi(curMax)
	if err != nil {
		logrus.Errorf("Unexpected error: %v", err)
		return 0, err
	}

	// If new value is higher than the existing one, then let's update this
	// new value into the container struct but not push it down to the kernel.
	if newMinInt > curMinInt {
		cntr.SetData(path, name, newMin)

		return len(req.Data), nil
	}

	if kernelSync {
		if err := pushFileMinInt(h, n, cntr, newMinInt); err != nil {
			return 0, io.EOF
		}
	}

	// Writing the new value into container-state struct.
	cntr.SetData(path, name, newMin)

	return len(req.Data), nil
}

func writeInt(
	h domain.HandlerIface,
	n domain.IOnodeIface,
	req *domain.HandlerRequest,
	min, max int,
	kernelSync bool) (int, error) {

	name := n.Name()
	path := n.Path()
	cntr := req.Container

	// Ensure operation is generated from within a registered sys container.
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return 0, errors.New("Container not found")
	}

	newVal := strings.TrimSpace(string(req.Data))
	newValInt, err := strconv.Atoi(newVal)
	if err != nil {
		return 0, fuse.IOerror{Code: syscall.EINVAL}
	}

	if newValInt < min || newValInt > max {
		return 0, fuse.IOerror{Code: syscall.EINVAL}
	}

	cntr.Lock()
	defer cntr.Unlock()

	// Check if this resource has been initialized for this container. If not,
	// push it down to the kernel and store it within the container struct.
	curVal, ok := cntr.Data(path, name)
	if !ok {
		if kernelSync {
			if err := pushFileInt(h, n, cntr, newValInt); err != nil {
				return 0, err
			}
		}

		cntr.SetData(path, name, newVal)

		return len(req.Data), nil
	}

	// Return if new value matches the existing one.
	if newVal == curVal {
		return len(req.Data), nil
	}

	if kernelSync {
		if err := pushFileInt(h, n, cntr, newValInt); err != nil {
			return 0, io.EOF
		}
	}

	// Writing the new value into container-state struct.
	cntr.SetData(path, name, newVal)

	return len(req.Data), nil
}

func writeString(
	h domain.HandlerIface,
	n domain.IOnodeIface,
	req *domain.HandlerRequest,
	kernelSync bool) (int, error) {

	name := n.Name()
	path := n.Path()
	cntr := req.Container

	// Ensure operation is generated from within a registered sys container.
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)",
			req.Pid)
		return 0, errors.New("Container not found")
	}

	newStr := strings.TrimSpace(string(req.Data))

	cntr.Lock()
	defer cntr.Unlock()

	// Check if this resource has been initialized for this container. If not,
	// push it down to the kernel and store it within the container struct.
	curStr, ok := cntr.Data(path, name)
	if !ok {
		if kernelSync {
			if err := pushFileString(h, n, cntr, newStr); err != nil {
				return 0, err
			}
		}

		cntr.SetData(path, name, newStr)

		return len(req.Data), nil
	}

	// Return if no change is detected.
	if newStr == curStr {
		return len(req.Data), nil
	}

	if kernelSync {
		if err := pushFileString(h, n, cntr, newStr); err != nil {
			return 0, io.EOF
		}
	}

	// Writing the new value into container-state struct.
	cntr.SetData(path, name, newStr)

	return len(req.Data), nil
}

func pushFileMaxInt(
	h domain.HandlerIface,
	n domain.IOnodeIface,
	c domain.ContainerIface,
	newMaxInt int) error {

	// We need the per-resource lock since we are about to access the resource on
	// the host FS and multiple sys containers could be accessing that same
	// resource concurrently.
	//
	// But that's not sufficient. Some users may deploy sysbox inside a
	// privileged container, and thus can have multiple sysbox instances running
	// concurrently on the same host. If those sysbox instances write conflicting
	// values to a kernel resource that uses this handler (e.g., a sysctl under
	// /proc/sys), a race condition arises that could cause the value to be
	// written to not be the max across all instances.
	//
	// To reduce the chance of this occurring, in addition to the per-resource
	// lock, we use a heuristic in which we read-after-write to verify the value
	// of the resource is larger or equal to the one we wrote. If it isn't, it
	// means some other agent on the host wrote a smaller value to the resource
	// after we wrote to it, so we must retry the write.
	//
	// When retrying, we wait a small but random amount of time to reduce the
	// chance of hitting the race condition again. And we retry a limited amount
	// of times.
	//
	// Note that this solution works well for resolving race conditions among
	// sysbox instances, but may not address race conditions with other host
	// agents that write to the same sysctl. That's because there is no guarantee
	// that the other host agent will read-after-write and retry as sysbox does.

	hmux := h.GetMutex()
	hmux.Lock()
	defer hmux.Unlock()

	retries := 5
	retryDelay := 100 // microsecs

	for i := 0; i < retries; i++ {

		curHostMax, err := n.ReadLine()
		if err != nil && err != io.EOF {
			return err
		}
		curHostMaxInt, err := strconv.Atoi(curHostMax)
		if err != nil {
			logrus.Errorf("Unexpected error: %v", err)
			return err
		}

		// If the existing host value is larger than the new one to configure,
		// then let's just return here as we want to keep the largest value
		// in the host kernel.
		if newMaxInt <= curHostMaxInt {
			return nil
		}

		// When retrying, wait a random delay to reduce chances of a new collision
		if i > 0 {
			d := rand.Intn(retryDelay)
			time.Sleep(time.Duration(d) * time.Microsecond)
		}

		// Push down to host kernel the new (larger) value.
		msg := []byte(strconv.Itoa(newMaxInt))
		err = n.WriteFile(msg)
		if err != nil && !h.GetService().IgnoreErrors() {
			logrus.Errorf("Could not write to file %s, error %s",
				n.Path(), err)
			return err
		}
	}

	return nil
}

func pushFileMinInt(
	h domain.HandlerIface,
	n domain.IOnodeIface,
	c domain.ContainerIface,
	val int) error {

	// We need the per-resource lock since we are about to access the resource
	// on the host FS. See pushFileMaxInt() for a full explanation.
	hmux := h.GetMutex()
	hmux.Lock()
	defer hmux.Unlock()

	retries := 5
	retryDelay := 100 // microsecs

	for i := 0; i < retries; i++ {

		curHostMin, err := n.ReadLine()
		if err != nil && err != io.EOF {
			return err
		}
		curHostMinInt, err := strconv.Atoi(curHostMin)
		if err != nil {
			logrus.Errorf("Unexpected error: %v", err)
			return err
		}

		// If the existing host value is smaller than the new one to configure,
		// then let's just return here as we want to keep the smallest value
		// in the host kernel.
		if val >= curHostMinInt {
			return nil
		}

		// When retrying, wait a random delay to reduce chances of a new collision
		if i > 0 {
			d := rand.Intn(retryDelay)
			time.Sleep(time.Duration(d) * time.Microsecond)
		}

		// Push down to host kernel the new (larger) value.
		msg := []byte(strconv.Itoa(val))
		err = n.WriteFile(msg)
		if err != nil && !h.GetService().IgnoreErrors() {
			logrus.Errorf("Could not write to file %s, error %s",
				n.Path(), err)
			return err
		}
	}

	return nil
}

func pushFileInt(
	h domain.HandlerIface,
	n domain.IOnodeIface,
	c domain.ContainerIface,
	val int) error {

	// TODO: Review this and similar comments above: a handler-lock is not
	// necessarily a per-resource lock; they are not the same. Also, mention
	// something about being unable in this case (string) to use the heuristic
	// of the above push methods above.
	//
	// We need the per-resource lock since we are about to access the resource
	// on the host FS.
	hmux := h.GetMutex()
	hmux.Lock()
	defer hmux.Unlock()

	curHostVal, err := n.ReadLine()
	if err != nil && err != io.EOF {
		return err
	}
	curHostValInt, err := strconv.Atoi(curHostVal)
	if err != nil {
		logrus.Errorf("Unexpected error: %v", err)
		return err
	}

	// If the existing string in the host fully matches the one to be defined,
	// then there's no need to proceed.
	if val == curHostValInt {
		return nil
	}

	// Push down to host kernel the new string.
	err = n.WriteFile([]byte(strconv.Itoa(val)))
	if err != nil && !h.GetService().IgnoreErrors() {
		logrus.Errorf("Could not write to file %s, error %s",
			n.Path(), err)
		return err
	}

	return nil
}

func pushFileString(
	h domain.HandlerIface,
	n domain.IOnodeIface,
	c domain.ContainerIface,
	str string) error {

	// TODO: Review this and similar comments above: a handler-lock is not
	// necessarily a per-resource lock; they are not the same. Also, mention
	// something about being unable in this case (string) to use the heuristic
	// of the above push methods above.
	//
	// We need the per-resource lock since we are about to access the resource
	// on the host FS.
	hmux := h.GetMutex()
	hmux.Lock()
	defer hmux.Unlock()

	curHostStr, err := n.ReadLine()
	if err != nil && err != io.EOF {
		return err
	}

	// If the existing string in the host fully matches the one to be defined,
	// then there's no need to proceed.
	if str == curHostStr {
		return nil
	}

	// Push down to host kernel the new string.
	err = n.WriteFile([]byte(str))
	if err != nil && !h.GetService().IgnoreErrors() {
		logrus.Errorf("Could not write to file %s, error %s",
			n.Path(), err)
		return err
	}

	return nil
}

// copytResultBuffer function copies the obtained 'result' buffer into the 'I/O'
// buffer supplied by the user, while ensuring that 'I/O' buffer capacity is not
// exceeded.
func copyResultBuffer(ioBuf []byte, result []byte) (int, error) {

	var length int

	resultLen := len(result)
	ioBufLen := len(ioBuf)

	// Adjust the number of bytes to copy based on the ioBuf capacity.
	if ioBufLen < resultLen {
		copy(ioBuf, result[:ioBufLen])
		length = ioBufLen
	} else {
		copy(ioBuf[:resultLen], result)
		length = resultLen
	}

	return length, nil
}
