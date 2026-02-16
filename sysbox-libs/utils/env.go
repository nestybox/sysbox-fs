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

package utils

import (
	"fmt"
	"os/exec"
	"strings"
)

// GetEnvVarInfo returns the name and value of the given environment variable
func GetEnvVarInfo(v string) (string, string, error) {
	tokens := strings.Split(v, "=")
	if len(tokens) != 2 {
		return "", "", fmt.Errorf("invalid variable %s", v)
	}
	return tokens[0], tokens[1], nil
}

// CmdExists check if the given command is available on the host
func CmdExists(name string) bool {
	cmd := exec.Command("/bin/sh", "-c", "command -v "+name)
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}
