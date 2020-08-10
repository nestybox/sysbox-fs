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

package sysio

/*
//
// ioNodeBuffer specialization. Enhances the regular bytes.Buffer class by
// providing ReadAt() and Close() methods in order to satisfy ioNode interface.
// Utilized in UT scenarios.
//

type ioConfigBuffer struct {
	data []byte
}

type ioNodeBuffer struct {
	bytes.Buffer
}

func newNodeBuffer(cfgIntf IOconfig) IOnode {

	config := cfgIntf.(*ioConfigBuffer)
	if config == nil {
		return nil
	}

	newNode := ioNodeBuffer{
		Buffer: *(bytes.NewBuffer(config.data)),
	}

	return &newNode
}

func newNodeBufferString(s string) *ioNodeBuffer {
	var newnode ioNodeBuffer

	newnode.Buffer = *(bytes.NewBufferString(s))

	return &newnode
}

func (i *ioNodeBuffer) ReadAt(p []byte, offset int64) (int, error) {
	// TODO: Implement a proper readAt() method for this class.
	return i.Buffer.Read(p)
}

func (i *ioNodeBuffer) Close() error {

	i.Buffer.Reset()
	return nil
}

func (i *ioNodeBuffer) WriteString(s string) int {

	n, _ := i.Buffer.WriteString(s)

	return n
}
*/
