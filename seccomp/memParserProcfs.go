//
// Copyright 2022 Nestybox, Inc.
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

package seccomp

import (
	"C"
	"fmt"
)
import (
	"bufio"
	"io"
	"os"
	"strings"
)

// File hosts memParser specialization logic to allow interaction with seccomp tracee's
// through the '/proc/pid/mem' interface. Note that this approach is expected to be
// less performant than the scatter-gather (IOvec) one, but is needed to support systems
// where this option is not available.

type memParserProcfs struct {}

// ReadSyscallStringArgs iterates through the tracee's process /proc/pid/mem file to
// identify string (i.e., null-terminated) arguments utilized by the traced syscall.
// The assumption here is that the process invoking the syscall is 'stopped' at the
// time that this routine is executed. That is, tracee runs within a a single
// execution context (single-thread), and thefore its memory can be safely referenced.
func (mp *memParserProcfs) ReadSyscallStringArgs(pid uint32, elems []memParserDataElem) ([]string, error) {

	if len(elems) == 0 {
		return nil, nil
	}

	name := fmt.Sprintf("/proc/%d/mem", pid)
	f, err := os.Open(name)
	if err != nil {
			return nil, fmt.Errorf("failed to open %s: %s", name, err)
	}
	defer f.Close()

	result := make([]string, len(elems))

	reader := bufio.NewReader(f)
	var line string

	// Iterate through the memory locations passed by caller.
	for i, e := range elems {
			if e.addr == 0 {
					result[i] = ""
			} else {
					reader.Reset(f)
					_, err := f.Seek(int64(e.addr), 0)
					if err != nil {
							return nil, fmt.Errorf("seek of %s failed: %s", name, err)
					}
					line, err = reader.ReadString('\x00')
					if err != nil {
							return nil, fmt.Errorf("read of %s at offset %d failed: %s",
								 name, e.addr, err)
					}
					result[i] = strings.TrimSuffix(line, "\x00")
			}
	}

	return result, nil
}

// ReadSyscallBytesArgs iterates through the tracee's process /proc/pid/mem file to
// identify arbitrary byte data arguments utilized by the traced syscall.
func (mp *memParserProcfs) ReadSyscallBytesArgs(pid uint32, elems []memParserDataElem) ([]string, error) {

	if len(elems) == 0 {
		return nil, nil
	}

	name := fmt.Sprintf("/proc/%d/mem", pid)
	f, err := os.Open(name)
	if err != nil {
			return nil, fmt.Errorf("failed to open %s: %s", name, err)
	}
	defer f.Close()

	result := make([]string, len(elems))
	reader := bufio.NewReader(f)

	for i, e := range elems {
			if e.addr == 0 {
					result[i] = string([]byte{})
			} else {
					reader.Reset(f)
					_, err := f.Seek(int64(e.addr), 0)
					if err != nil {
							return nil, fmt.Errorf("seek of %s failed: %s", name, err)
					}

					// read the number of bytes specified by "size" (exactly)
					byteData := make([]byte, e.size)
					_, err = io.ReadFull(reader, byteData)
					if err != nil {
							return nil, fmt.Errorf("read of %s at offset %d with size %d failed: %s",
								 name, e.addr, e.size, err)
					}

					result[i] = string(byteData)
			}
	}

	return result, nil
}

// WriteSyscallBytesArgs writes collected state (i.e. syscall responses) into the
// the tracee's address space. This is accomplished by writing into the tracee's
// process /proc/pid/mem file.
func (mp *memParserProcfs) WriteSyscallBytesArgs(pid uint32, elems []memParserDataElem) error {

	if len(elems) == 0 {
		return nil
	}

	name := fmt.Sprintf("/proc/%d/mem", pid)
	f, err := os.OpenFile(name, os.O_RDWR, 0600)
	if err != nil {
			return fmt.Errorf("failed to open %s: %s", name, err)
	}
	defer f.Close()

	writer := bufio.NewWriter(f)

	for _, e := range elems {

		data := e.data[:e.size]

		if e.addr == 0 {
			continue
		} else {
			writer.Reset(f)
			_, err := f.Seek(int64(e.addr), 0)
			if err != nil {
				return fmt.Errorf("seek of %s failed: %s", name, err)
			}

			_, err = writer.Write(data)
			if err != nil {
				return fmt.Errorf("write of %s at offset %d with size %d failed: %s",
					name, e.addr, e.size, err)
			}

			if err = writer.Flush(); err != nil {
				return fmt.Errorf("write of %s at offset %d with size %d failed: %s",
					name, e.addr, e.size, err)
			}
		}
	}

	return nil
}
