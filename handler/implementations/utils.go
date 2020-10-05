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
	"fmt"
	"os"

	"github.com/nestybox/sysbox-fs/domain"
)

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

// EmulatedFilesInfo is a handler aid that finds files within the given
// directory node that are emulated by sysbox-fs. It returns a map that lists
// each file's name and it's info.
func emulatedFilesInfo(hs domain.HandlerServiceIface,
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (map[string]os.FileInfo, error) {

	var emulatedResources []string

	// Obtain a list of all the emulated resources falling within the current
	// directory.
	emulatedResources = hs.DirHandlerEntries(n.Path())
	if len(emulatedResources) == 0 {
		return nil, nil
	}

	var emulatedFilesInfo = make(map[string]os.FileInfo)

	// For every emulated resource, invoke its Lookup() handler to obtain
	// the information required to satisfy this ongoing readDirAll()
	// instruction.
	for _, handlerPath := range emulatedResources {

		// Lookup the associated handler within handler-DB.
		handler, ok := hs.FindHandler(handlerPath)
		if !ok {
			return nil, fmt.Errorf("No supported handler for %v resource", handlerPath)
		}

		// Create temporary ionode to represent handler-path.
		ios := hs.IOService()
		newIOnode := ios.NewIOnode("", handlerPath, 0)

		// Handler execution.
		info, err := handler.Lookup(newIOnode, req)
		if err != nil {
			if !hs.IgnoreErrors() {
				return nil, fmt.Errorf("Lookup for %v failed: %s", handlerPath, err)
			} else {
				return nil, nil
			}
		}

		emulatedFilesInfo[info.Name()] = info
	}

	return emulatedFilesInfo, nil
}
