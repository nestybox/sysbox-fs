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

// memParser interface defines the set of operations required to interact
// with seccomp-tracee processes to extract/inject state from/into their
// address-spaces.
type memParser interface {
	ReadSyscallStringArgs(pid uint32, elems []memParserDataElem) ([]string, error)
	ReadSyscallBytesArgs(pid uint32, elems []memParserDataElem) ([]string, error)
	WriteSyscallBytesArgs(pid uint32, elems []memParserDataElem) error
}

type memParserDataElem struct {
	addr uint64   // mem address in tracee's address space
	size int      // size of the data element to read / write
	data []byte   // data to write to tracee's address space
}
