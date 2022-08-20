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

package implementations

import (
	"errors"
	"io"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
	"github.com/sirupsen/logrus"
)

func readCntrData(
	h domain.HandlerIface,
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	cntr := req.Container
	path := n.Path()

	cntr.Lock()
	defer cntr.Unlock()

	// Check if this resource is cached for this container. If it isn't, fetch
	// its data from the host FS and cache it within the container struct.

	sz, err := cntr.Data(path, req.Offset, &req.Data)
	if err != nil && err != io.EOF {
		return 0, fuse.IOerror{Code: syscall.EINVAL}
	}

	if req.Offset == 0 && sz == 0 && err == io.EOF {

		sz, err = readFs(h, n, req.Offset, &req.Data)
		if err != nil && err != io.EOF {
			return 0, fuse.IOerror{Code: syscall.EINVAL}
		}

		if sz == 0 && err == io.EOF {
			return 0, nil
		}

		err = cntr.SetData(path, req.Offset, req.Data[0:sz])
		if err != nil {
			return 0, fuse.IOerror{Code: syscall.EINVAL}
		}
	}

	return sz, nil
}

func writeCntrData(
	h domain.HandlerIface,
	n domain.IOnodeIface,
	req *domain.HandlerRequest,
	pushToFs func(currData, newData []byte) (bool, error)) (int, error) {

	cntr := req.Container
	path := n.Path()
	ignoreFsErrors := h.GetService().IgnoreErrors()

	cntr.Lock()
	defer cntr.Unlock()

	sz, err := writeFs(h, n, req.Offset, req.Data, pushToFs)

	if ignoreFsErrors {
		err = nil
		sz = len(req.Data)
	}

	if err != nil {
		logrus.Errorf("Failed to write to %s: %s", path, err)
		return 0, err
	}

	err = cntr.SetData(path, req.Offset, req.Data)
	if err != nil {
		return 0, fuse.IOerror{Code: syscall.EINVAL}
	}

	return sz, nil
}

// readFs reads data from the given IO node.
func readFs(
	h domain.HandlerIface,
	n domain.IOnodeIface,
	offset int64,
	data *[]byte) (int, error) {

	// We need the per-resource lock since we are about to access the resource
	// on the host FS. See writeFs() for a full explanation.
	resourceMutex := h.GetResourceMutex(n)

	if resourceMutex == nil {
		logrus.Errorf("Unexpected error: no mutex found for emulated resource %s",
			n.Path())
		return 0, errors.New("no mutex found for emulated resource")
	}
	resourceMutex.Lock()
	defer resourceMutex.Unlock()

	// Read from the host FS to extract the existing value.
	if err := n.Open(); err != nil {
		logrus.Errorf("Could not open file %v", n.Path())
		return 0, err
	}
	defer n.Close()

	// TODO: ReadAt may not read all data; check sz and loop until we read all
	// the data
	sz, err := n.ReadAt(*data, offset)
	if err != nil && err != io.EOF {
		logrus.Errorf("Could not read from file %v at offset %d", n.Path(), offset)
		return 0, err
	}

	return sz, err
}

// Same as above but without concurrency protection. To be utilized only when
// reading from non-emulated nodes.
func readHostFs(
	h domain.HandlerIface,
	n domain.IOnodeIface,
	offset int64,
	data *[]byte) (int, error) {

	// Read from the host FS to extract the existing value.
	if err := n.Open(); err != nil {
		logrus.Errorf("Could not open file %v", n.Path())
		return 0, err
	}
	defer n.Close()

	// TODO: ReadAt may not read all data; check sz and loop until we read all
	// the data
	sz, err := n.ReadAt(*data, offset)
	if err != nil && err != io.EOF {
		logrus.Errorf("Could not read from file %v at offset %d", n.Path(), offset)
		return 0, err
	}

	return sz, err
}

// writeFs writes the given data to the given IO node. argument 'wrCondition'
// is a function that the caller can pass to determine if the write should
// actually happen given the IO node's current and new data. If set to nil
// the write is skipped.
func writeFs(
	h domain.HandlerIface,
	n domain.IOnodeIface,
	offset int64,
	data []byte,
	wrCondition func(currData, newData []byte) (bool, error)) (int, error) {

	if wrCondition == nil {
		return len(data), nil
	}

	// We need the per-resource lock since we are about to access the resource
	// on the host FS and multiple sys containers could be accessing that same
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
	// of the resource is equal to the one we wrote. If it isn't, it means some
	// other agent on the host wrote a value to the resource after we wrote to
	// it, so we must retry the write.
	//
	// When retrying, we wait a small but random amount of time to reduce the
	// chance of hitting the race condition again. And we retry a limited amount
	// of times.
	//
	// Note that this solution works well for resolving race conditions among
	// sysbox instances, but may not address race conditions with other host
	// agents that write to the same sysctl. That's because there is no guarantee
	// that the other host agent will read-after-write and retry as sysbox does.

	resourceMutex := h.GetResourceMutex(n)

	if resourceMutex == nil {
		logrus.Errorf("Unexpected error: no mutex found for emulated resource %s",
			n.Path())
		return 0, errors.New("no mutex found for emulated resource")
	}
	resourceMutex.Lock()
	defer resourceMutex.Unlock()

	n.SetOpenFlags(int(os.O_RDWR))
	if err := n.Open(); err != nil {
		return 0, err
	}
	defer n.Close()

	retries := 5
	retryDelay := 100 // microsecs
	currData := make([]byte, 65536, 65536)

	for i := 0; i < retries; i++ {

		// TODO: ReadAt may not read all data; check sz and loop until we read all
		// the data
		sz, err := n.ReadAt(currData, offset)
		if err != nil && err != io.EOF {
			return 0, err
		}
		currData = currData[0:sz]

		if string(currData) == string(data) {
			break
		}

		write, err := wrCondition(currData, data)
		if err != nil {
			return 0, err
		}

		if !write {
			break
		}

		// When retrying, wait a random delay to reduce chances of a new collision.
		if i > 0 {
			d := rand.Intn(retryDelay)
			time.Sleep(time.Duration(d) * time.Microsecond)
		}

		// TODO: WriteAt may not write all data; check sz and loop until we write
		// all the data
		_, err = n.WriteAt(data, offset)
		if err != nil {
			return 0, err
		}
	}

	return len(data), nil
}

// Returns true unconditionally; meant to be used as the 'wrCondition' argument in writeFs()
func writeToFs(curr, new []byte) (bool, error) {
	return true, nil
}

// Same as above but without concurrency protection. To be utilized only when
// writing into non-emulated nodes.
func writeHostFs(
	h domain.HandlerIface,
	n domain.IOnodeIface,
	offset int64,
	data []byte) (int, error) {

	n.SetOpenFlags(int(os.O_RDWR))
	if err := n.Open(); err != nil {
		return 0, err
	}
	defer n.Close()

	_, err := n.WriteAt(data, offset)
	if err != nil {
		return 0, err
	}

	return len(data), nil
}

// writeMaxIntToFs interprets the given data as integers and returns true if new > curr; meant
// to be used at the 'wrCondition' argument in writeFs()
func writeMaxIntToFs(curr, new []byte) (bool, error) {

	newStr := strings.TrimSpace(string(new))
	newInt, err := strconv.Atoi(newStr)
	if err != nil {
		return false, err
	}

	currStr := strings.TrimSpace(string(curr))
	currInt, err := strconv.Atoi(currStr)
	if err != nil {
		return false, err
	}

	return newInt > currInt, nil
}

// writeMinIntToFs interprets the given data as integers and returns true if new < curr; meant
// to be used at the 'wrCondition' argument in writeFs()
func writeMinIntToFs(curr, new []byte) (bool, error) {

	newStr := strings.TrimSpace(string(new))
	newInt, err := strconv.Atoi(newStr)
	if err != nil {
		return false, err
	}

	currStr := strings.TrimSpace(string(curr))
	currInt, err := strconv.Atoi(currStr)
	if err != nil {
		return false, err
	}

	return newInt < currInt, nil
}

// checkIntRange interprets the given data as an integer and checks if it's
// within the given range (inclusive).
func checkIntRange(data []byte, min, max int) bool {
	str := strings.TrimSpace(string(data))
	val, err := strconv.Atoi(str)
	if err != nil {
		return false
	}

	if val < min || val > max {
		return false
	}

	return true
}

func padRight(str, pad string, length int) string {
	for {
		str += pad
		if len(str) > length {
			return str[0:length]
		}
	}
}

func padLeft(str, pad string, length int) string {
	for {
		str = pad + str
		if len(str) > length {
			return str[0:length]
		}
	}
}
