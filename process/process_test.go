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

package process

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/nestybox/sysbox-fs/domain"
	cap "github.com/nestybox/sysbox-libs/capability"
)

func TestCheckPermOwner(t *testing.T) {

	tmpDir, err := ioutil.TempDir("/tmp", "TestPathres")
	if err != nil {
		t.Fatalf("failed to create test dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	filename := filepath.Join(tmpDir, "testFile")
	_, err = os.Create(filename)
	if err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}
	if err := os.Chmod(filename, 0664); err != nil {
		t.Fatalf("failed to chmod test file: %v", err)
	}

	p := &process{
		root: tmpDir,
		cwd:  tmpDir,
		uid:  uint32(os.Geteuid()),
		gid:  uint32(os.Getegid()),
	}

	mode := domain.R_OK | domain.W_OK
	ok, err := p.checkPerm(filename, mode)
	if err != nil || !ok {
		t.Fatalf("checkPerm() failed: ok = %v, err = %v", ok, err)
	}

	// check no execute perm
	mode = domain.X_OK
	ok, err = p.checkPerm(filename, mode)
	if err != nil || ok {
		t.Fatalf("checkPerm() failed: ok = %v, err = %v", ok, err)
	}
}

func TestCheckPermGroup(t *testing.T) {

	tmpDir, err := ioutil.TempDir("/tmp", "TestPathres")
	if err != nil {
		t.Fatalf("failed to create test dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	filename := filepath.Join(tmpDir, "testFile")
	_, err = os.Create(filename)
	if err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}
	if err := os.Chmod(filename, 0664); err != nil {
		t.Fatalf("failed to chmod test file: %v", err)
	}

	// check group perm
	p := &process{
		root: tmpDir,
		cwd:  tmpDir,
		uid:  800,
		gid:  uint32(os.Getegid()),
	}

	mode := domain.R_OK | domain.W_OK
	ok, err := p.checkPerm(filename, mode)
	if err != nil || !ok {
		t.Fatalf("checkPerm() failed: ok = %v, err = %v", ok, err)
	}

	// check suppl group perm
	p = &process{
		root: tmpDir,
		cwd:  tmpDir,
		uid:  800,
		gid:  800,
		sgid: []int{os.Getegid()},
	}

	mode = domain.R_OK | domain.W_OK
	ok, err = p.checkPerm(filename, mode)
	if err != nil || !ok {
		t.Fatalf("checkPerm() failed: ok = %v, err = %v", ok, err)
	}

	// check no execute perm
	mode = domain.X_OK
	ok, err = p.checkPerm(filename, mode)
	if err != nil || ok {
		t.Fatalf("checkPerm() failed: ok = %v, err = %v", ok, err)
	}
}

func TestCheckPermOther(t *testing.T) {

	tmpDir, err := ioutil.TempDir("/tmp", "TestPathres")
	if err != nil {
		t.Fatalf("failed to create test dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	filename := filepath.Join(tmpDir, "testFile")
	_, err = os.Create(filename)
	if err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}
	if err := os.Chmod(filename, 0664); err != nil {
		t.Fatalf("failed to chmod test file: %v", err)
	}

	// check other perm
	p := &process{
		root: tmpDir,
		cwd:  tmpDir,
		uid:  800,
		gid:  800,
	}

	mode := domain.R_OK
	ok, err := p.checkPerm(filename, mode)
	if err != nil || !ok {
		t.Fatalf("checkPerm() failed: ok = %v, err = %v", ok, err)
	}

	// check no write or execute perm
	mode = domain.W_OK | domain.X_OK
	ok, err = p.checkPerm(filename, mode)
	if err != nil || ok {
		t.Fatalf("checkPerm() failed: ok = %v, err = %v", ok, err)
	}
}

func TestCheckPermCapDacOverride(t *testing.T) {

	tmpDir, err := ioutil.TempDir("/tmp", "TestPathres")
	if err != nil {
		t.Fatalf("failed to create test dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	filename := filepath.Join(tmpDir, "testFile")
	_, err = os.Create(filename)
	if err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// File has execute-by-owner only; CAP_DAC_OVERRIDE will allow rwx on it
	if err := os.Chmod(filename, 0100); err != nil {
		t.Fatalf("failed to chmod test file: %v", err)
	}

	p := &process{
		root: tmpDir,
		cwd:  tmpDir,
		uid:  800,
		gid:  800,
	}

	p.setCapability(cap.EFFECTIVE, cap.CAP_DAC_OVERRIDE)

	mode := domain.R_OK | domain.W_OK | domain.X_OK
	ok, err := p.checkPerm(filename, mode)
	if err != nil || !ok {
		t.Fatalf("checkPerm() failed: ok = %v, err = %v", ok, err)
	}

	// File has no permissions; CAP_DAC_OVERRIDE will allow rw on it, but not execute.
	if err := os.Chmod(filename, 0000); err != nil {
		t.Fatalf("failed to chmod test file: %v", err)
	}

	mode = domain.R_OK | domain.W_OK
	ok, err = p.checkPerm(filename, mode)
	if err != nil || !ok {
		t.Fatalf("checkPerm() failed: ok = %v, err = %v", ok, err)
	}

	mode = domain.X_OK
	ok, err = p.checkPerm(filename, mode)
	if err != nil || ok {
		t.Fatalf("checkPerm() failed: ok = %v, err = %v", ok, err)
	}
}

func TestCheckPermCapDacReadSearch(t *testing.T) {

	tmpDir, err := ioutil.TempDir("/tmp", "TestPathres")
	if err != nil {
		t.Fatalf("failed to create test dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	filename := filepath.Join(tmpDir, "testFile")
	_, err = os.Create(filename)
	if err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// File has no permissions; CAP_DAC_READ_SEARCH allows read on it
	if err := os.Chmod(filename, 0000); err != nil {
		t.Fatalf("failed to chmod test file: %v", err)
	}

	p := &process{
		pid:  uint32(os.Getpid()),
		root: tmpDir,
		cwd:  tmpDir,
		uid:  800,
		gid:  800,
	}

	// Init caps explicitly to prevent p.setCapability() below from loading caps for the current process.
	p.cap, err = cap.NewPid2(int(p.pid))
	if err != nil {
		t.Fatalf("failed to allocate capabilities: %v", err)
	}

	p.setCapability(cap.EFFECTIVE, cap.CAP_DAC_READ_SEARCH)

	mode := domain.R_OK
	ok, err := p.checkPerm(filename, mode)
	if err != nil || !ok {
		t.Fatalf("checkPerm() failed: ok = %v, err = %v", ok, err)
	}

	// Directory has no perm; CAP_DAC_READ_SEARCH allows read and execute on it
	dirname := filepath.Join(tmpDir, "testDir")
	err = os.MkdirAll(dirname, 0000)
	if err != nil {
		t.Fatalf("failed to create test path: %v", err)
	}

	mode = domain.R_OK | domain.X_OK
	ok, err = p.checkPerm(dirname, mode)
	if err != nil || !ok {
		t.Fatalf("checkPerm() failed: ok = %v, err = %v", ok, err)
	}

	// CAP_DAC_READ_SEARCH does not allow writes
	mode = domain.W_OK
	ok, err = p.checkPerm(filename, mode)
	if err != nil || ok {
		t.Fatalf("checkPerm() failed: ok = %v, err = %v", ok, err)
	}
	ok, err = p.checkPerm(dirname, mode)
	if err != nil || ok {
		t.Fatalf("checkPerm() failed: ok = %v, err = %v", ok, err)
	}
}

func TestProcPathAccess(t *testing.T) {

	tmpDir, err := ioutil.TempDir("/tmp", "TestPathres")
	if err != nil {
		t.Fatalf("failed to create test dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	path := filepath.Join(tmpDir, "/some/path/to/a/dir")
	err = os.MkdirAll(path, 0755)
	if err != nil {
		t.Fatalf("failed to create test path: %v", err)
	}

	cwd := filepath.Join(tmpDir, "/some/path/to")

	p := &process{
		procroot: tmpDir,
		proccwd:  cwd,
		uid:      uint32(os.Geteuid()),
		gid:      uint32(os.Getegid()),
	}

	mode := domain.R_OK | domain.W_OK | domain.X_OK

	if err := p.pathAccess("a/dir", mode); err != nil {
		t.Fatalf("pathAccess() failed: %v", err)
	}

	// test handling of repeated "/"
	if err := p.pathAccess("a////dir", mode); err != nil {
		t.Fatalf("pathAccess() failed: %v", err)
	}

	// test handling of "."
	if err := p.pathAccess("./a/dir", mode); err != nil {
		t.Fatalf("pathAccess() failed: %v", err)
	}

	if err := p.pathAccess("a/dir/.", mode); err != nil {
		t.Fatalf("pathAccess() failed: %v", err)
	}

	if err := p.pathAccess("././a/./dir/.", mode); err != nil {
		t.Fatalf("pathAccess() failed: %v", err)
	}

	// test handling of ".."
	if err := p.pathAccess("../to/a/dir", mode); err != nil {
		t.Fatalf("pathAccess() failed: %v", err)
	}

	if err := p.pathAccess("../../path/to/a/dir", mode); err != nil {
		t.Fatalf("pathAccess() failed: %v", err)
	}

	if err := p.pathAccess("../../../some/path/to/a/dir", mode); err != nil {
		t.Fatalf("pathAccess() failed: %v", err)
	}

	if err := p.pathAccess("../../../../some/path/to/a/dir", mode); err != nil {
		t.Fatalf("pathAccess() failed: %v", err)
	}

	if err := p.pathAccess("a/../a/dir", mode); err != nil {
		t.Fatalf("pathAccess() failed: %v", err)
	}

	if err := p.pathAccess("a/../a/../../to/a/dir", mode); err != nil {
		t.Fatalf("pathAccess() failed: %v", err)
	}

	if err := p.pathAccess("../../../../../../../some/path/../path/to/a/dir", mode); err != nil {
		t.Fatalf("pathAccess() failed: %v", err)
	}

	if err := p.pathAccess("../to/a/dir/..", mode); err != nil {
		t.Fatalf("pathAccess() failed: %v", err)
	}

	// combine all of the above
	if err := p.pathAccess("../../../../.././../.././///some/path/../path///to/./a/dir////", mode); err != nil {
		t.Fatalf("pathAccess() failed: %v", err)
	}
}

func TestProcPathAccessDirAndFilePerm(t *testing.T) {

	tmpDir, err := ioutil.TempDir("/tmp", "TestPathres")
	if err != nil {
		t.Fatalf("failed to create test dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	path := filepath.Join(tmpDir, "/some/path/to/a/dir")
	err = os.MkdirAll(path, 0755)
	if err != nil {
		t.Fatalf("failed to create test path: %v", err)
	}

	filename := filepath.Join(path, "somefile")
	_, err = os.Create(filename)
	if err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	cwd := filepath.Join(tmpDir, "/some/path/to")

	p := &process{
		procroot: tmpDir,
		proccwd:  cwd,
		uid:      uint32(os.Geteuid()),
		gid:      uint32(os.Getegid()),
	}

	if err := p.pathAccess("/some/path/to/a/dir/somefile", 0); err != nil {
		t.Fatalf("pathAccess() failed: %v", err)
	}

	// Restrict access on the file and verify
	if err := os.Chmod(filename, 0700); err != nil {
		t.Fatalf("failed to chmod test file: %v", err)
	}

	p = &process{
		pid:      uint32(os.Getpid()),
		procroot: tmpDir,
		proccwd:  cwd,
		uid:      800,
		gid:      800,
	}

	// Initialize the process caps
	p.cap, err = cap.NewPid2(int(p.pid))
	if err != nil {
		t.Fatalf("failed to allocate capabilities: %v", err)
	}

	if err := p.pathAccess("/some/path/to/a/dir/somefile", 0); err != nil {
		t.Fatalf("procPathAccess() failed: %v", err)
	}

	if err := p.pathAccess("/some/path/to/a/dir/somefile", domain.R_OK); err != syscall.EACCES {
		t.Fatalf("pathAccess() expected to fail with \"%s\" but did not; err = \"%s\"", syscall.EACCES, err)
	}
	if err := p.pathAccess("/some/path/to/a/dir/somefile", domain.W_OK); err != syscall.EACCES {
		t.Fatalf("pathAccess() expected to fail with \"%s\" but did not; err = \"%s\"", syscall.EACCES, err)
	}
	if err := p.pathAccess("/some/path/to/a/dir/somefile", domain.X_OK); err != syscall.EACCES {
		t.Fatalf("pathAccess() expected to fail with \"%s\" but did not; err = \"%s\"", syscall.EACCES, err)
	}

	// Restrict access on a dir of the path and verify
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatalf("failed to chmod test file: %v", err)
	}
	if err := os.Chmod(filename, 0777); err != nil {
		t.Fatalf("failed to chmod test file: %v", err)
	}
	if err := p.pathAccess(
		"/some/path/to/a/dir/somefile",
		domain.R_OK|domain.W_OK|domain.X_OK); err != syscall.EACCES {
		t.Fatalf("pathAccess() expected to fail with \"%s\" but did not; err = \"%s\"", syscall.EACCES, err)
	}

	p = &process{
		procroot: tmpDir,
		proccwd:  cwd,
		uid:      uint32(os.Geteuid()),
		gid:      uint32(os.Getegid()),
	}

	if err := p.pathAccess(
		"/some/path/to/a/dir/somefile",
		domain.R_OK|domain.W_OK|domain.X_OK); err != nil {
		t.Fatalf("pathAccess() failed: %v", err)
	}
}

func TestProcPathAccessEnoent(t *testing.T) {

	tmpDir, err := ioutil.TempDir("/tmp", "TestPathres")
	if err != nil {
		t.Fatalf("failed to create test dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	path := filepath.Join(tmpDir, "/some/path/to/a/dir")
	err = os.MkdirAll(path, 0755)
	if err != nil {
		t.Fatalf("failed to create test path: %v", err)
	}

	cwd := filepath.Join(tmpDir, "/some/path/to")

	p := &process{
		root: tmpDir,
		cwd:  cwd,
		uid:  uint32(os.Geteuid()),
		gid:  uint32(os.Getegid()),
	}

	mode := domain.R_OK

	if err = p.pathAccess("a/non/existent/dir", mode); err != syscall.ENOENT {
		goto Fail
	}

	if err = p.pathAccess("../to/a/non/existent/dir", mode); err != syscall.ENOENT {
		goto Fail
	}

	if err = p.pathAccess("a/dir/../bad", mode); err != syscall.ENOENT {
		goto Fail
	}

	if err = p.pathAccess("a/dir/../../bad", mode); err != syscall.ENOENT {
		goto Fail
	}

	if err = p.pathAccess("a/dir/../../../../../../../bad", mode); err != syscall.ENOENT {
		goto Fail
	}

	if err = p.pathAccess("a/./bad/./dir/", mode); err != syscall.ENOENT {
		goto Fail
	}

	if err = p.pathAccess("/some/path/to/a/non/existent/dir", mode); err != syscall.ENOENT {
		goto Fail
	}

	return

Fail:
	t.Fatalf("procPathAccess() expected to fail with \"%s\" but did not; err = \"%s\"", syscall.ENOENT, err)
}

func TestProcPathAccessSymlink(t *testing.T) {

	// This test creates the following dir and symlink hierarchy and verifies all
	// symlinks get resolved correctly.
	//
	// /tmp/TestPathres/
	// ├── another
	// │   └── path
	// │       ├── again
	// │       │   └── link4 -> ../../path/link3
	// │       └── link3 -> /link2
	// ├── link -> /this/is/the/real/path
	// ├── link2 -> /link
	// └── this
	//     └── is
	//         └── the
	//             └── real
	//                 └── path

	tmpDir, err := ioutil.TempDir("/tmp", "TestPathres")
	if err != nil {
		t.Fatalf("failed to create test dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	path := filepath.Join(tmpDir, "/this/is/the/real/path")
	err = os.MkdirAll(path, 0755)
	if err != nil {
		t.Fatalf("failed to create test path: %v", err)
	}

	old := "./this/is/the/real/path"
	new := filepath.Join(tmpDir, "/link")
	if err := os.Symlink(old, new); err != nil {
		t.Fatalf("failed to create test path: %v", err)
	}

	p := &process{
		procroot: tmpDir,
		proccwd:  tmpDir,
		uid:      uint32(os.Geteuid()),
		gid:      uint32(os.Getegid()),
	}

	mode := domain.R_OK | domain.X_OK

	if err := p.pathAccess("/link", mode); err != nil {
		t.Fatalf("pathAccess() failed: %v", err)
	}

	if err := p.pathAccess("/link/..", mode); err != nil {
		t.Fatalf("pathAccess() failed: %v", err)
	}

	// test recursive symlinks
	old = "/link"
	new = filepath.Join(tmpDir, "/link2")
	if err := os.Symlink(old, new); err != nil {
		t.Fatalf("failed to create test path: %v", err)
	}

	if err := p.pathAccess("/link2", mode); err != nil {
		t.Fatalf("pathAccess() failed: %v", err)
	}

	path = filepath.Join(tmpDir, "/another/path")
	err = os.MkdirAll(path, 0755)
	if err != nil {
		t.Fatalf("failed to create test path: %v", err)
	}

	old = "/link2"
	new = filepath.Join(tmpDir, "/another/path/link3")
	if err := os.Symlink(old, new); err != nil {
		t.Fatalf("failed to create test path: %v", err)
	}

	if err := p.pathAccess("/another/path/link3", mode); err != nil {
		t.Fatalf("pathAccess() failed: %v", err)
	}

	path = filepath.Join(tmpDir, "/another/path/again")
	err = os.MkdirAll(path, 0755)
	if err != nil {
		t.Fatalf("failed to create test path: %v", err)
	}

	// test relative symlink
	testCwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed on os.Getwd(): %v", err)
	}

	if err := os.Chdir(filepath.Join(tmpDir, "/another/path/again")); err != nil {
		t.Fatalf("failed on os.Chdir(): %v", err)
	}

	if err := os.Symlink("../../path/link3", "link4"); err != nil {
		t.Fatalf("failed to create test path: %v", err)
	}

	if err := p.pathAccess("/another/path/again/link4", mode); err != nil {
		t.Fatalf("pathAccess() failed: %v", err)
	}

	if err := p.pathAccess("/another/path/again/link4/..", mode); err != nil {
		t.Fatalf("pathAccess() failed: %v", err)
	}

	if err := os.Chdir(testCwd); err != nil {
		t.Fatalf("failed on os.Chdir(): %v", err)
	}

	//
	// Reproducing corner case exposed by issue #574, observed during execution
	// initialization of an inner container ("mount -o bind,remount .").
	//
	// /tmp/TestPathres/
	// |-- cwdLink  ->  /
	// |-- rootLink ->  /
	//

	cwd := filepath.Join(tmpDir, "/cwdLink")
	if err := os.Symlink("/", cwd); err != nil {
		t.Fatalf("failed to create test path: %v", err)
	}
	root := filepath.Join(tmpDir, "/rootLink")
	if err := os.Symlink("/", root); err != nil {
		t.Fatalf("failed to create test path: %v", err)
	}

	p = &process{
		procroot: root,
		proccwd:  cwd,
		uid:      uint32(os.Geteuid()),
		gid:      uint32(os.Getegid()),
	}

	if err := p.pathAccess(".", mode); err != nil {
		t.Fatalf("pathAccess() failed: %v", err)
	}
}

func TestPathAccess(t *testing.T) {

	p := &process{pid: uint32(os.Getpid())}

	tmpDir, err := ioutil.TempDir("/tmp", "TestPathres")
	if err != nil {
		t.Fatalf("failed to create test dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	path := filepath.Join(tmpDir, "/some/path/to/a/dir")

	err = os.MkdirAll(path, 0755)
	if err != nil {
		t.Fatalf("failed to create test path: %v", err)
	}

	filename := filepath.Join(path, "somefile")
	_, err = os.Create(filename)
	if err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// file access
	if err := p.PathAccess(filename, domain.R_OK|domain.W_OK); err != nil {
		t.Fatalf("PathAccess() failed: %v", err)
	}

	// dir access
	path = tmpDir + "/some/path/to/a/dir"
	if err := p.PathAccess(
		path,
		domain.R_OK|domain.X_OK); err != nil {
		t.Fatalf("PathAccess() failed: %v", err)
	}

	// .. and .
	path = tmpDir + "/some/path/../../some/path/to/a/./dir/somefile"
	if err := p.PathAccess(
		path,
		domain.R_OK|domain.W_OK); err != nil {
		t.Fatalf("PathAccess() failed: %v", err)
	}

	path = tmpDir + "/some/path/../../some/path/to/a/./dir/./././"
	if err := p.PathAccess(
		path,
		domain.R_OK|domain.X_OK); err != nil {
		t.Fatalf("PathAccess() failed: %v", err)
	}

	path = tmpDir + "/../../../../" + tmpDir + "/some/path/to/a/../a/dir/."
	if err := p.PathAccess(
		path,
		domain.R_OK|domain.X_OK); err != nil {
		t.Fatalf("PathAccess() failed: %v", err)
	}

	// relative paths

	testCwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed on os.Getwd(): %v", err)
	}

	if err := os.Chdir(filepath.Join(tmpDir, "/some/path")); err != nil {
		t.Fatalf("failed on os.Chdir(): %v", err)
	}

	path = "to/a/dir/somefile"
	if err := p.PathAccess(
		path,
		domain.R_OK|domain.W_OK); err != nil {
		t.Fatalf("PathAccess() failed: %v", err)
	}

	if err := os.Chdir(filepath.Join(tmpDir, "/some/path/to")); err != nil {
		t.Fatalf("failed on os.Chdir(): %v", err)
	}

	path = "a/dir"
	if err := p.PathAccess(
		path,
		domain.R_OK|domain.X_OK); err != nil {
		t.Fatalf("PathAccess() failed: %v", err)
	}

	if err := os.Chdir(testCwd); err != nil {
		t.Fatalf("failed on os.Chdir(): %v", err)
	}
}

func TestPathAccessPerm(t *testing.T) {
	var err error

	p := &process{pid: uint32(os.Getpid())}

	// Initialize the process caps
	p.cap, err = cap.NewPid2(int(p.pid))
	if err != nil {
		t.Fatalf("failed to allocate capabilities: %v", err)
	}

	tmpDir, err := ioutil.TempDir("/tmp", "TestPathres")
	if err != nil {
		t.Fatalf("failed to create test dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	path := filepath.Join(tmpDir, "/some/path/to/a/dir")

	err = os.MkdirAll(path, 0755)
	if err != nil {
		t.Fatalf("failed to create test path: %v", err)
	}

	filename := filepath.Join(path, "somefile")
	_, err = os.Create(filename)
	if err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// read-only
	if err := os.Chmod(filename, 0400); err != nil {
		t.Fatalf("failed to chmod test file: %v", err)
	}

	if err := p.PathAccess(filename, domain.R_OK); err != nil {
		t.Fatalf("PathAccess() failed: %v", err)
	}

	if err := p.PathAccess(filename, domain.W_OK); err != syscall.EACCES {
		t.Fatalf("PathAccess() expected to fail with \"%s\" but did not; err = \"%s\"", syscall.EACCES, err)
	}

	if err := p.PathAccess(filename, domain.X_OK); err != syscall.EACCES {
		t.Fatalf("PathAccess() expected to fail with \"%s\" but did not; err = \"%s\"", syscall.EACCES, err)
	}

	// write-only
	if err := os.Chmod(filename, 0200); err != nil {
		t.Fatalf("failed to chmod test file: %v", err)
	}

	if err := p.PathAccess(filename, domain.W_OK); err != nil {
		t.Fatalf("PathAccess() failed: %v", err)
	}

	if err := p.PathAccess(filename, domain.R_OK); err != syscall.EACCES {
		t.Fatalf("PathAccess() expected to fail with \"%s\" but did not; err = \"%s\"", syscall.EACCES, err)
	}

	if err := p.PathAccess(filename, domain.X_OK); err != syscall.EACCES {
		t.Fatalf("PathAccess() expected to fail with \"%s\" but did not; err = \"%s\"", syscall.EACCES, err)
	}

	// execute-only
	if err := os.Chmod(filename, 0100); err != nil {
		t.Fatalf("failed to chmod test file: %v", err)
	}

	if err := p.PathAccess(filename, domain.X_OK); err != nil {
		t.Fatalf("PathAccess() failed: %v", err)
	}

	if err := p.PathAccess(filename, domain.R_OK); err != syscall.EACCES {
		t.Fatalf("PathAccess() expected to fail with \"%s\" but did not; err = \"%s\"", syscall.EACCES, err)
	}

	if err := p.PathAccess(filename, domain.W_OK); err != syscall.EACCES {
		t.Fatalf("PathAccess() expected to fail with \"%s\" but did not; err = \"%s\"", syscall.EACCES, err)
	}

	// dir read-only
	if err := os.Chmod(filename, 0777); err != nil {
		t.Fatalf("failed to chmod test file: %v", err)
	}

	if err := os.Chmod(path, 0400); err != nil {
		t.Fatalf("failed to chmod test file: %v", err)
	}

	if err := p.PathAccess(filename, domain.R_OK); err != syscall.EACCES {
		t.Fatalf("PathAccess() expected to fail with \"%s\" but did not; err = \"%s\"", syscall.EACCES, err)
	}
}

func TestPathAccessSymlink(t *testing.T) {

	p := &process{pid: uint32(os.Getpid())}

	tmpDir, err := ioutil.TempDir("/tmp", "TestPathres")
	if err != nil {
		t.Fatalf("failed to create test dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	path := filepath.Join(tmpDir, "/this/is/the/real/path")
	err = os.MkdirAll(path, 0755)
	if err != nil {
		t.Fatalf("failed to create test path: %v", err)
	}

	filename := filepath.Join(path, "somefile")
	_, err = os.Create(filename)
	if err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// test absolute symlink

	link := filepath.Join(tmpDir, "/link")
	if err := os.Symlink(filename, link); err != nil {
		t.Fatalf("failed to create test path: %v", err)
	}

	if err := p.PathAccess(link, domain.R_OK|domain.W_OK); err != nil {
		t.Fatalf("PathAccess() failed: %v", err)
	}

	// test relative symlink

	testCwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed on os.Getwd(): %v", err)
	}

	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed on os.Chdir(): %v", err)
	}

	if err := p.PathAccess("link", domain.R_OK|domain.W_OK); err != nil {
		t.Fatalf("PathAccess() failed: %v", err)
	}

	if err := os.Chdir(testCwd); err != nil {
		t.Fatalf("failed on os.Chdir(): %v", err)
	}

	// negative test on file perm

	if err := p.PathAccess(filename, domain.X_OK); err != syscall.EACCES {
		t.Fatalf("PathAccess() expected to fail with \"%s\" but did not; err = \"%s\"", syscall.EACCES, err)
	}
}

// TODO:
// * test symlink resolution limit
// * test long path
