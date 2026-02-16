//
// Copyright 2019-2022 Nestybox, Inc.
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
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestSysboxPidFile(t *testing.T) {

	testDir, err := ioutil.TempDir("", "sysbox-mgr-test")
	if err != nil {
		t.Errorf(err.Error())
	}
	defer os.RemoveAll(testDir)

	pidFile := filepath.Join(testDir, "sysbox-mgr.pid")

	// create sysbox pid file
	if err := CreatePidFile("sysbox-mgr", pidFile); err != nil {
		t.Errorf("CreatePidFile() failed: %s", err)
	}

	// verify
	_, err = os.Stat(pidFile)
	if err != nil {
		t.Errorf("failed to stat %s: %s", pidFile, err)
	}

	// create again -- should pass given that there's no actual instance of
	// sysbox-mgr running in the system.
	if err := CreatePidFile("sysbox-mgr", pidFile); err != nil {
		t.Errorf("CreatePidFile() failed: %s", err)
	}

	// destroy the pid file
	if err := DestroyPidFile(pidFile); err != nil {
		t.Errorf("DestroyPidFile() failed: %s", err)
	}

	// verify
	_, err = os.Stat(pidFile)
	if err == nil || !os.IsNotExist(err) {
		t.Errorf("pid file %s was not removed", pidFile)
		os.RemoveAll(pidFile)
	}
}
