//
// Copyright: (C) 2020 Nestybox Inc.  All rights reserved.
//

// Copyright (c) 2013, Suryandaru Triandana <syndtr@gmail.com>
// All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package capability

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"syscall"
)

var errUnknownVers = errors.New("unknown capability version")

const (
	linuxCapVer1 = 0x19980330
	linuxCapVer2 = 0x20071026
	linuxCapVer3 = 0x20080522
)

var (
	capVers uint32

	capLastCap Cap

	// Highest valid capability of the running kernel.
	CAP_LAST_CAP = Cap(63)

	capUpperMask = ^uint32(0)

	pkgInitialized = false
	initMutex      sync.RWMutex
)

func initialize() {
	var hdr capHeader
	capget(&hdr, nil)
	capVers = hdr.version

	if initLastCap() == nil {
		CAP_LAST_CAP = capLastCap
		if capLastCap > 31 {
			capUpperMask = (uint32(1) << (uint(capLastCap) - 31)) - 1
		} else {
			capUpperMask = 0
		}
	}

	initMutex.Lock()
	pkgInitialized = true
	initMutex.Unlock()
}

func initLastCap() error {
	if capLastCap != 0 {
		return nil
	}

	f, err := os.Open("/proc/sys/kernel/cap_last_cap")
	if err != nil {
		return err
	}
	defer f.Close()

	var b []byte = make([]byte, 11)
	_, err = f.Read(b)
	if err != nil {
		return err
	}

	fmt.Sscanf(string(b), "%d", &capLastCap)

	return nil
}

func mkStringCap(c Capabilities, which CapType, format CapFormat) (ret string) {
	for i, first := Cap(0), true; i <= CAP_LAST_CAP; i++ {
		if !c.Get(which, i) {
			continue
		}
		if first {
			first = false
		} else {
			ret += ", "
		}
		if format == OCI_STRING {
			ret += i.OCIString()
		} else {
			ret += i.String()
		}
	}
	return
}

func mkString(c Capabilities, max CapType, format CapFormat) (ret string) {
	ret = "{"
	for i := CapType(1); i <= max; i <<= 1 {
		ret += " " + i.String() + "=\""
		if c.Empty(i) {
			ret += "empty"
		} else if c.Full(i) {
			ret += "full"
		} else {
			ret += c.StringCap(i, format)
		}
		ret += "\""
	}
	ret += " }"
	return
}

func initializationCompleted() bool {
	initMutex.RLock()
	res := pkgInitialized
	initMutex.RUnlock()

	return res
}

func newPid(pid int) (c Capabilities, err error) {

	if !initializationCompleted() {
		initialize()
	}

	switch capVers {
	case linuxCapVer2, linuxCapVer3:
		p := new(capsV3)
		p.hdr.version = capVers
		p.hdr.pid = int32(pid)
		c = p
	default:
		err = errUnknownVers
		return
	}
	return
}

type capsV3 struct {
	hdr     capHeader
	data    [2]capData
	bounds  [2]uint32
	ambient [2]uint32
}

func (c *capsV3) Get(which CapType, what Cap) bool {
	var i uint
	if what > 31 {
		i = uint(what) >> 5
		what %= 32
	}

	switch which {
	case EFFECTIVE:
		return (1<<uint(what))&c.data[i].effective != 0
	case PERMITTED:
		return (1<<uint(what))&c.data[i].permitted != 0
	case INHERITABLE:
		return (1<<uint(what))&c.data[i].inheritable != 0
	case BOUNDING:
		return (1<<uint(what))&c.bounds[i] != 0
	case AMBIENT:
		return (1<<uint(what))&c.ambient[i] != 0
	}

	return false
}

func (c *capsV3) getData(which CapType, dest []uint32) {
	switch which {
	case EFFECTIVE:
		dest[0] = c.data[0].effective
		dest[1] = c.data[1].effective
	case PERMITTED:
		dest[0] = c.data[0].permitted
		dest[1] = c.data[1].permitted
	case INHERITABLE:
		dest[0] = c.data[0].inheritable
		dest[1] = c.data[1].inheritable
	case BOUNDING:
		dest[0] = c.bounds[0]
		dest[1] = c.bounds[1]
	case AMBIENT:
		dest[0] = c.ambient[0]
		dest[1] = c.ambient[1]
	}
}

// Sysbox's method addition.
func (c *capsV3) GetEffCaps() [2]uint32 {

	var data [2]uint32
	c.getData(EFFECTIVE, data[:])

	return data
}

// Sysbox's method addition.
func (c *capsV3) SetEffCaps(caps [2]uint32) {

	if len(caps) != 2 {
		return
	}

	c.data[0].effective = caps[0]
	c.data[1].effective = caps[1]
}

func (c *capsV3) Empty(which CapType) bool {
	var data [2]uint32
	c.getData(which, data[:])
	return data[0] == 0 && data[1] == 0
}

func (c *capsV3) Full(which CapType) bool {
	var data [2]uint32
	c.getData(which, data[:])
	if (data[0] & 0xffffffff) != 0xffffffff {
		return false
	}
	return (data[1] & capUpperMask) == capUpperMask
}

func (c *capsV3) Set(which CapType, caps ...Cap) {
	for _, what := range caps {
		var i uint
		if what > 31 {
			i = uint(what) >> 5
			what %= 32
		}

		if which&EFFECTIVE != 0 {
			c.data[i].effective |= 1 << uint(what)
		}
		if which&PERMITTED != 0 {
			c.data[i].permitted |= 1 << uint(what)
		}
		if which&INHERITABLE != 0 {
			c.data[i].inheritable |= 1 << uint(what)
		}
		if which&BOUNDING != 0 {
			c.bounds[i] |= 1 << uint(what)
		}
		if which&AMBIENT != 0 {
			c.ambient[i] |= 1 << uint(what)
		}
	}
}

func (c *capsV3) Unset(which CapType, caps ...Cap) {
	for _, what := range caps {
		var i uint
		if what > 31 {
			i = uint(what) >> 5
			what %= 32
		}

		if which&EFFECTIVE != 0 {
			c.data[i].effective &= ^(1 << uint(what))
		}
		if which&PERMITTED != 0 {
			c.data[i].permitted &= ^(1 << uint(what))
		}
		if which&INHERITABLE != 0 {
			c.data[i].inheritable &= ^(1 << uint(what))
		}
		if which&BOUNDING != 0 {
			c.bounds[i] &= ^(1 << uint(what))
		}
		if which&AMBIENT != 0 {
			c.ambient[i] &= ^(1 << uint(what))
		}
	}
}

func (c *capsV3) Fill(kind CapType) {
	if kind&CAPS == CAPS {
		c.data[0].effective = 0xffffffff
		c.data[0].permitted = 0xffffffff
		c.data[0].inheritable = 0
		c.data[1].effective = 0xffffffff
		c.data[1].permitted = 0xffffffff
		c.data[1].inheritable = 0
	}

	if kind&BOUNDS == BOUNDS {
		c.bounds[0] = 0xffffffff
		c.bounds[1] = 0xffffffff
	}
	if kind&AMBS == AMBS {
		c.ambient[0] = 0xffffffff
		c.ambient[1] = 0xffffffff
	}
}

func (c *capsV3) ClearOriginal(kind CapType) {
	if kind&CAPS == CAPS {
		c.data[0].effective = 0
		c.data[0].permitted = 0
		c.data[0].inheritable = 0
		c.data[1].effective = 0
		c.data[1].permitted = 0
		c.data[1].inheritable = 0
	}

	if kind&BOUNDS == BOUNDS {
		c.bounds[0] = 0
		c.bounds[1] = 0
	}
	if kind&AMBS == AMBS {
		c.ambient[0] = 0
		c.ambient[1] = 0
	}
}

// Sysbox implementation of the original Clear() method (see above). In this
// implementation we are handling every CAPS category separately to allow any
// capability-type (kind) to be individually updated.
func (c *capsV3) Clear(kind CapType) {
	if kind&EFFECTIVE == EFFECTIVE {
		c.data[0].effective = 0
		c.data[1].effective = 0
	}
	if kind&PERMITTED == PERMITTED {
		c.data[0].permitted = 0
		c.data[1].permitted = 0
	}
	if kind&INHERITABLE == INHERITABLE {
		c.data[0].inheritable = 0
		c.data[1].inheritable = 0
	}

	if kind&BOUNDS == BOUNDS {
		c.bounds[0] = 0
		c.bounds[1] = 0
	}
	if kind&AMBS == AMBS {
		c.ambient[0] = 0
		c.ambient[1] = 0
	}
}

func (c *capsV3) StringCap(which CapType, format CapFormat) (ret string) {
	return mkStringCap(c, which, format)
}

func (c *capsV3) String(format CapFormat) (ret string) {
	return mkString(c, BOUNDING, format)
}

func (c *capsV3) LoadOriginal() (err error) {
	err = capget(&c.hdr, &c.data[0])
	if err != nil {
		return
	}

	var status_path string

	if c.hdr.pid == 0 {
		status_path = fmt.Sprintf("/proc/self/status")
	} else {
		status_path = fmt.Sprintf("/proc/%d/status", c.hdr.pid)
	}

	f, err := os.Open(status_path)
	if err != nil {
		return
	}
	b := bufio.NewReader(f)
	for {
		line, e := b.ReadString('\n')
		if e != nil {
			if e != io.EOF {
				err = e
			}
			break
		}
		if strings.HasPrefix(line, "CapB") {
			fmt.Sscanf(line[4:], "nd:  %08x%08x", &c.bounds[1], &c.bounds[0])
			continue
		}
		if strings.HasPrefix(line, "CapA") {
			fmt.Sscanf(line[4:], "mb:  %08x%08x", &c.ambient[1], &c.ambient[0])
			continue
		}
	}
	f.Close()

	return
}

// Sysbox implementation of the original Load() method (see above). For
// efficiency purposes, in this case we are not parsing 'status' file to
// extract 'ambient' and 'bounding' capabilities.
func (c *capsV3) Load() (err error) {
	err = capget(&c.hdr, &c.data[0])
	if err != nil {
		return
	}

	return
}

func (c *capsV3) Apply(kind CapType) (err error) {
	if kind&BOUNDS == BOUNDS {
		var data [2]capData
		err = capget(&c.hdr, &data[0])
		if err != nil {
			return
		}
		if (1<<uint(CAP_SETPCAP))&data[0].effective != 0 {
			for i := Cap(0); i <= CAP_LAST_CAP; i++ {
				if c.Get(BOUNDING, i) {
					continue
				}
				err = prctl(syscall.PR_CAPBSET_DROP, uintptr(i), 0, 0, 0)
				if err != nil {
					// Ignore EINVAL since the capability may not be supported in this system.
					if errno, ok := err.(syscall.Errno); ok && errno == syscall.EINVAL {
						err = nil
						continue
					}
					return
				}
			}
		}
	}

	if kind&CAPS == CAPS {
		err = capset(&c.hdr, &c.data[0])
		if err != nil {
			return
		}
	}

	if kind&AMBS == AMBS {
		for i := Cap(0); i <= CAP_LAST_CAP; i++ {
			action := pr_CAP_AMBIENT_LOWER
			if c.Get(AMBIENT, i) {
				action = pr_CAP_AMBIENT_RAISE
			}
			err := prctl(pr_CAP_AMBIENT, action, uintptr(i), 0, 0)
			// Ignore EINVAL as not supported on kernels before 4.3
			if errno, ok := err.(syscall.Errno); ok && errno == syscall.EINVAL {
				err = nil
				continue
			}
		}
	}

	return
}

func newFile(path string) (c Capabilities, err error) {
	c = &capsFile{path: path}
	return
}

type capsFile struct {
	path string
	data vfscapData
}

func (c *capsFile) Get(which CapType, what Cap) bool {
	var i uint
	if what > 31 {
		if c.data.version == 1 {
			return false
		}
		i = uint(what) >> 5
		what %= 32
	}

	switch which {
	case EFFECTIVE:
		return (1<<uint(what))&c.data.effective[i] != 0
	case PERMITTED:
		return (1<<uint(what))&c.data.data[i].permitted != 0
	case INHERITABLE:
		return (1<<uint(what))&c.data.data[i].inheritable != 0
	}

	return false
}

func (c *capsFile) getData(which CapType, dest []uint32) {
	switch which {
	case EFFECTIVE:
		dest[0] = c.data.effective[0]
		dest[1] = c.data.effective[1]
	case PERMITTED:
		dest[0] = c.data.data[0].permitted
		dest[1] = c.data.data[1].permitted
	case INHERITABLE:
		dest[0] = c.data.data[0].inheritable
		dest[1] = c.data.data[1].inheritable
	}
}

// Sysbox's method addition.
func (c *capsFile) GetEffCaps() [2]uint32 {

	var data [2]uint32
	c.getData(EFFECTIVE, data[:])

	return data
}

// Sysbox's method addition.
func (c *capsFile) SetEffCaps(caps [2]uint32) {

	if len(caps) != 2 {
		return
	}

	c.data.effective[0] = caps[0]
	c.data.effective[1] = caps[1]
}

func (c *capsFile) Empty(which CapType) bool {
	var data [2]uint32
	c.getData(which, data[:])
	return data[0] == 0 && data[1] == 0
}

func (c *capsFile) Full(which CapType) bool {
	var data [2]uint32
	c.getData(which, data[:])
	if c.data.version == 0 {
		return (data[0] & 0x7fffffff) == 0x7fffffff
	}
	if (data[0] & 0xffffffff) != 0xffffffff {
		return false
	}
	return (data[1] & capUpperMask) == capUpperMask
}

func (c *capsFile) Set(which CapType, caps ...Cap) {
	for _, what := range caps {
		var i uint
		if what > 31 {
			if c.data.version == 1 {
				continue
			}
			i = uint(what) >> 5
			what %= 32
		}

		if which&EFFECTIVE != 0 {
			c.data.effective[i] |= 1 << uint(what)
		}
		if which&PERMITTED != 0 {
			c.data.data[i].permitted |= 1 << uint(what)
		}
		if which&INHERITABLE != 0 {
			c.data.data[i].inheritable |= 1 << uint(what)
		}
	}
}

func (c *capsFile) Unset(which CapType, caps ...Cap) {
	for _, what := range caps {
		var i uint
		if what > 31 {
			if c.data.version == 1 {
				continue
			}
			i = uint(what) >> 5
			what %= 32
		}

		if which&EFFECTIVE != 0 {
			c.data.effective[i] &= ^(1 << uint(what))
		}
		if which&PERMITTED != 0 {
			c.data.data[i].permitted &= ^(1 << uint(what))
		}
		if which&INHERITABLE != 0 {
			c.data.data[i].inheritable &= ^(1 << uint(what))
		}
	}
}

func (c *capsFile) Fill(kind CapType) {
	if kind&CAPS == CAPS {
		c.data.effective[0] = 0xffffffff
		c.data.data[0].permitted = 0xffffffff
		c.data.data[0].inheritable = 0
		if c.data.version == 2 {
			c.data.effective[1] = 0xffffffff
			c.data.data[1].permitted = 0xffffffff
			c.data.data[1].inheritable = 0
		}
	}
}

func (c *capsFile) Clear(kind CapType) {
	if kind&CAPS == CAPS {
		c.data.effective[0] = 0
		c.data.data[0].permitted = 0
		c.data.data[0].inheritable = 0
		if c.data.version == 2 {
			c.data.effective[1] = 0
			c.data.data[1].permitted = 0
			c.data.data[1].inheritable = 0
		}
	}
}

func (c *capsFile) StringCap(which CapType, format CapFormat) (ret string) {
	return mkStringCap(c, which, format)
}

func (c *capsFile) String(format CapFormat) (ret string) {
	return mkString(c, INHERITABLE, format)
}

func (c *capsFile) Load() (err error) {
	return getVfsCap(c.path, &c.data)
}

func (c *capsFile) Apply(kind CapType) (err error) {
	if kind&CAPS == CAPS {
		return setVfsCap(c.path, &c.data)
	}
	return
}
