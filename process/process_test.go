package process

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestGetProcInfo(t *testing.T) {

	groups, err := os.Getgroups()
	if err != nil {
		t.Fatalf("Getgroups() failed: %v", err)
	}

	mypid := os.Getpid()

	want := &procInfo{
		root: fmt.Sprintf("/proc/%d/root", mypid),
		cwd:  fmt.Sprintf("/proc/%d/cwd", mypid),
		uid:  os.Geteuid(),
		gid:  os.Getegid(),
		sgid: groups,
		cap:  0,
	}

	got, err := getProcInfo(os.Getpid())
	if err != nil {
		t.Fatalf("getProcInfo failed: %v", err)
	}

	if !reflect.DeepEqual(*want, *got) {
		t.Fatalf("getProcInfo failed: want %+v; got %+v", want, got)
	}
}

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

	// check owner perm
	pi := &procInfo{
		root: tmpDir,
		cwd:  tmpDir,
		uid:  os.Geteuid(),
		gid:  os.Getegid(),
	}

	mode := R_OK | W_OK
	ok, err := checkPerm(pi, filename, mode)
	if err != nil || !ok {
		t.Fatalf("checkPerm() failed: ok = %v, err = %v", ok, err)
	}

	// check no execute perm
	mode = X_OK
	ok, err = checkPerm(pi, filename, mode)
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
	pi := &procInfo{
		root: tmpDir,
		cwd:  tmpDir,
		uid:  800,
		gid:  os.Getegid(),
	}

	mode := R_OK | W_OK
	ok, err := checkPerm(pi, filename, mode)
	if err != nil || !ok {
		t.Fatalf("checkPerm() failed: ok = %v, err = %v", ok, err)
	}

	// check suppl group perm
	pi = &procInfo{
		root: tmpDir,
		cwd:  tmpDir,
		uid:  800,
		gid:  800,
		sgid: []int{os.Getegid()},
	}

	mode = R_OK | W_OK
	ok, err = checkPerm(pi, filename, mode)
	if err != nil || !ok {
		t.Fatalf("checkPerm() failed: ok = %v, err = %v", ok, err)
	}

	// check no execute perm
	mode = X_OK
	ok, err = checkPerm(pi, filename, mode)
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
	pi := &procInfo{
		root: tmpDir,
		cwd:  tmpDir,
		uid:  800,
		gid:  800,
	}

	mode := R_OK
	ok, err := checkPerm(pi, filename, mode)
	if err != nil || !ok {
		t.Fatalf("checkPerm() failed: ok = %v, err = %v", ok, err)
	}

	// check no write or execute perm
	mode = W_OK | X_OK
	ok, err = checkPerm(pi, filename, mode)
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

	pi := &procInfo{
		root: tmpDir,
		cwd:  tmpDir,
		uid:  800,
		gid:  800,
		cap:  1 << unix.CAP_DAC_OVERRIDE,
	}

	mode := R_OK | W_OK | X_OK
	ok, err := checkPerm(pi, filename, mode)
	if err != nil || !ok {
		t.Fatalf("checkPerm() failed: ok = %v, err = %v", ok, err)
	}

	// File has no permissions; CAP_DAC_OVERRIDE will allow rw on it, but not execute.
	if err := os.Chmod(filename, 0000); err != nil {
		t.Fatalf("failed to chmod test file: %v", err)
	}

	mode = R_OK | W_OK
	ok, err = checkPerm(pi, filename, mode)
	if err != nil || !ok {
		t.Fatalf("checkPerm() failed: ok = %v, err = %v", ok, err)
	}

	mode = X_OK
	ok, err = checkPerm(pi, filename, mode)
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

	pi := &procInfo{
		root: tmpDir,
		cwd:  tmpDir,
		uid:  800,
		gid:  800,
		cap:  1 << unix.CAP_DAC_READ_SEARCH,
	}

	mode := R_OK
	ok, err := checkPerm(pi, filename, mode)
	if err != nil || !ok {
		t.Fatalf("checkPerm() failed: ok = %v, err = %v", ok, err)
	}

	// Directory has no perm; CAP_DAC_READ_SEARCH allows read and execute on it
	dirname := filepath.Join(tmpDir, "testDir")
	err = os.MkdirAll(dirname, 0000)
	if err != nil {
		t.Fatalf("failed to create test path: %v", err)
	}

	mode = R_OK | X_OK
	ok, err = checkPerm(pi, dirname, mode)
	if err != nil || !ok {
		t.Fatalf("checkPerm() failed: ok = %v, err = %v", ok, err)
	}

	// CAP_DAC_READ_SEARCH does not allow writes
	mode = W_OK
	ok, err = checkPerm(pi, filename, mode)
	if err != nil || ok {
		t.Fatalf("checkPerm() failed: ok = %v, err = %v", ok, err)
	}
	ok, err = checkPerm(pi, dirname, mode)
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
	pi := &procInfo{
		root: tmpDir,
		cwd:  cwd,
		uid:  os.Geteuid(),
		gid:  os.Getegid(),
	}

	mode := R_OK | W_OK | X_OK

	if err := procPathAccess(pi, "a/dir", mode); err != nil {
		t.Fatalf("procPathAccess() failed: %v", err)
	}

	// test handling of repeated "/"
	if err := procPathAccess(pi, "a////dir", mode); err != nil {
		t.Fatalf("procPathAccess() failed: %v", err)
	}

	// test handling of "."
	if err := procPathAccess(pi, "./a/dir", mode); err != nil {
		t.Fatalf("procPathAccess() failed: %v", err)
	}

	if err := procPathAccess(pi, "a/dir/.", mode); err != nil {
		t.Fatalf("procPathAccess() failed: %v", err)
	}

	if err := procPathAccess(pi, "././a/./dir/.", mode); err != nil {
		t.Fatalf("procPathAccess() failed: %v", err)
	}

	// test handling of ".."
	if err := procPathAccess(pi, "../to/a/dir", mode); err != nil {
		t.Fatalf("procPathAccess() failed: %v", err)
	}

	if err := procPathAccess(pi, "../../path/to/a/dir", mode); err != nil {
		t.Fatalf("procPathAccess() failed: %v", err)
	}

	if err := procPathAccess(pi, "../../../some/path/to/a/dir", mode); err != nil {
		t.Fatalf("procPathAccess() failed: %v", err)
	}

	if err := procPathAccess(pi, "../../../../some/path/to/a/dir", mode); err != nil {
		t.Fatalf("procPathAccess() failed: %v", err)
	}

	if err := procPathAccess(pi, "a/../a/dir", mode); err != nil {
		t.Fatalf("procPathAccess() failed: %v", err)
	}

	if err := procPathAccess(pi, "a/../a/../../to/a/dir", mode); err != nil {
		t.Fatalf("procPathAccess() failed: %v", err)
	}

	if err := procPathAccess(pi, "../../../../../../../some/path/../path/to/a/dir", mode); err != nil {
		t.Fatalf("procPathAccess() failed: %v", err)
	}

	if err := procPathAccess(pi, "../to/a/dir/..", mode); err != nil {
		t.Fatalf("procPathAccess() failed: %v", err)
	}

	// combine all of the above
	if err := procPathAccess(pi, "../../../../.././../.././///some/path/../path///to/./a/dir////", mode); err != nil {
		t.Fatalf("procPathAccess() failed: %v", err)
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
	pi := &procInfo{
		root: tmpDir,
		cwd:  cwd,
		uid:  os.Geteuid(),
		gid:  os.Getegid(),
	}

	if err := procPathAccess(pi, "/some/path/to/a/dir/somefile", 0); err != nil {
		t.Fatalf("procPathAccess() failed: %v", err)
	}

	// Restrict access on the file and verify
	if err := os.Chmod(filename, 0700); err != nil {
		t.Fatalf("failed to chmod test file: %v", err)
	}

	pi = &procInfo{
		root: tmpDir,
		cwd:  cwd,
		uid:  800,
		gid:  800,
	}

	if err := procPathAccess(pi, "/some/path/to/a/dir/somefile", 0); err != nil {
		t.Fatalf("procPathAccess() failed: %v", err)
	}
	if err := procPathAccess(pi, "/some/path/to/a/dir/somefile", R_OK); err != syscall.EACCES {
		t.Fatalf("procPathAccess() expected to fail with \"%s\" but did not; err = \"%s\"", syscall.EACCES, err)
	}
	if err := procPathAccess(pi, "/some/path/to/a/dir/somefile", W_OK); err != syscall.EACCES {
		t.Fatalf("procPathAccess() expected to fail with \"%s\" but did not; err = \"%s\"", syscall.EACCES, err)
	}
	if err := procPathAccess(pi, "/some/path/to/a/dir/somefile", X_OK); err != syscall.EACCES {
		t.Fatalf("procPathAccess() expected to fail with \"%s\" but did not; err = \"%s\"", syscall.EACCES, err)
	}

	// Restrict access on a dir of the path and verify
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatalf("failed to chmod test file: %v", err)
	}
	if err := os.Chmod(filename, 0777); err != nil {
		t.Fatalf("failed to chmod test file: %v", err)
	}
	if err := procPathAccess(pi, "/some/path/to/a/dir/somefile", R_OK|W_OK|X_OK); err != syscall.EACCES {
		t.Fatalf("procPathAccess() expected to fail with \"%s\" but did not; err = \"%s\"", syscall.EACCES, err)
	}

	pi = &procInfo{
		root: tmpDir,
		cwd:  cwd,
		uid:  os.Geteuid(),
		gid:  os.Getegid(),
	}

	if err := procPathAccess(pi, "/some/path/to/a/dir/somefile", R_OK|W_OK|X_OK); err != nil {
		t.Fatalf("procPathAccess() failed: %v", err)
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
	pi := &procInfo{
		root: tmpDir,
		cwd:  cwd,
		uid:  os.Geteuid(),
		gid:  os.Getegid(),
	}

	mode := R_OK

	if err = procPathAccess(pi, "a/non/existent/dir", mode); err != syscall.ENOENT {
		goto Fail
	}

	if err = procPathAccess(pi, "../to/a/non/existent/dir", mode); err != syscall.ENOENT {
		goto Fail
	}

	if err = procPathAccess(pi, "a/dir/../bad", mode); err != syscall.ENOENT {
		goto Fail
	}

	if err = procPathAccess(pi, "a/dir/../../bad", mode); err != syscall.ENOENT {
		goto Fail
	}

	if err = procPathAccess(pi, "a/dir/../../../../../../../bad", mode); err != syscall.ENOENT {
		goto Fail
	}

	if err = procPathAccess(pi, "a/./bad/./dir/", mode); err != syscall.ENOENT {
		goto Fail
	}

	if err = procPathAccess(pi, "/some/path/to/a/non/existent/dir", mode); err != syscall.ENOENT {
		goto Fail
	}

	return

Fail:
	t.Fatalf("procPathAccess() expected to fail with \"%s\" but did not; err = \"%s\"", syscall.ENOENT, err)
}

func TestProcPathAccessSymlink(t *testing.T) {

	// This test creates the following dir and symlink hierarchy and verifies all symlinks
	// get resolved correctly.
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

	old := "/this/is/the/real/path"
	new := filepath.Join(tmpDir, "/link")
	if err := os.Symlink(old, new); err != nil {
		t.Fatalf("failed to create test path: %v", err)
	}

	pi := &procInfo{
		root: tmpDir,
		cwd:  tmpDir,
		uid:  os.Geteuid(),
		gid:  os.Getegid(),
	}

	mode := R_OK | X_OK

	if err := procPathAccess(pi, "/link", mode); err != nil {
		t.Fatalf("procPathAccess() failed: %v", err)
	}

	if err := procPathAccess(pi, "/link/..", mode); err != nil {
		t.Fatalf("procPathAccess() failed: %v", err)
	}

	// test recursive symlinks
	old = "/link"
	new = filepath.Join(tmpDir, "/link2")
	if err := os.Symlink(old, new); err != nil {
		t.Fatalf("failed to create test path: %v", err)
	}

	if err := procPathAccess(pi, "/link2", mode); err != nil {
		t.Fatalf("procPathAccess() failed: %v", err)
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

	if err := procPathAccess(pi, "/another/path/link3", mode); err != nil {
		t.Fatalf("procPathAccess() failed: %v", err)
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

	if err := procPathAccess(pi, "/another/path/again/link4", mode); err != nil {
		t.Fatalf("procPathAccess() failed: %v", err)
	}

	if err := procPathAccess(pi, "/another/path/again/link4/..", mode); err != nil {
		t.Fatalf("procPathAccess() failed: %v", err)
	}

	if err := os.Chdir(testCwd); err != nil {
		t.Fatalf("failed on os.Chdir(): %v", err)
	}
}

func TestPathAccess(t *testing.T) {

	mypid := os.Getpid()

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
	if err := PathAccess(mypid, filename, R_OK|W_OK); err != nil {
		t.Fatalf("PathAccess() failed: %v", err)
	}

	// dir access
	path = tmpDir + "/some/path/to/a/dir"
	if err := PathAccess(mypid, path, R_OK|X_OK); err != nil {
		t.Fatalf("PathAccess() failed: %v", err)
	}

	// .. and .
	path = tmpDir + "/some/path/../../some/path/to/a/./dir/somefile"
	if err := PathAccess(mypid, path, R_OK|W_OK); err != nil {
		t.Fatalf("PathAccess() failed: %v", err)
	}

	path = tmpDir + "/some/path/../../some/path/to/a/./dir/./././"
	if err := PathAccess(mypid, path, R_OK|X_OK); err != nil {
		t.Fatalf("PathAccess() failed: %v", err)
	}

	path = tmpDir + "/../../../../" + tmpDir + "/some/path/to/a/../a/dir/."
	if err := PathAccess(mypid, path, R_OK|X_OK); err != nil {
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
	if err := PathAccess(mypid, path, R_OK|W_OK); err != nil {
		t.Fatalf("PathAccess() failed: %v", err)
	}

	if err := os.Chdir(filepath.Join(tmpDir, "/some/path/to")); err != nil {
		t.Fatalf("failed on os.Chdir(): %v", err)
	}

	path = "a/dir"
	if err := PathAccess(mypid, path, R_OK|X_OK); err != nil {
		t.Fatalf("PathAccess() failed: %v", err)
	}

	if err := os.Chdir(testCwd); err != nil {
		t.Fatalf("failed on os.Chdir(): %v", err)
	}
}

func TestPathAccessPerm(t *testing.T) {

	mypid := os.Getpid()

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

	if err := PathAccess(mypid, filename, R_OK); err != nil {
		t.Fatalf("PathAccess() failed: %v", err)
	}

	if err := PathAccess(mypid, filename, W_OK); err != syscall.EACCES {
		t.Fatalf("PathAccess() expected to fail with \"%s\" but did not; err = \"%s\"", syscall.EACCES, err)
	}

	if err := PathAccess(mypid, filename, X_OK); err != syscall.EACCES {
		t.Fatalf("PathAccess() expected to fail with \"%s\" but did not; err = \"%s\"", syscall.EACCES, err)
	}

	// write-only
	if err := os.Chmod(filename, 0200); err != nil {
		t.Fatalf("failed to chmod test file: %v", err)
	}

	if err := PathAccess(mypid, filename, W_OK); err != nil {
		t.Fatalf("PathAccess() failed: %v", err)
	}

	if err := PathAccess(mypid, filename, R_OK); err != syscall.EACCES {
		t.Fatalf("PathAccess() expected to fail with \"%s\" but did not; err = \"%s\"", syscall.EACCES, err)
	}

	if err := PathAccess(mypid, filename, X_OK); err != syscall.EACCES {
		t.Fatalf("PathAccess() expected to fail with \"%s\" but did not; err = \"%s\"", syscall.EACCES, err)
	}

	// execute-only
	if err := os.Chmod(filename, 0100); err != nil {
		t.Fatalf("failed to chmod test file: %v", err)
	}

	if err := PathAccess(mypid, filename, X_OK); err != nil {
		t.Fatalf("PathAccess() failed: %v", err)
	}

	if err := PathAccess(mypid, filename, R_OK); err != syscall.EACCES {
		t.Fatalf("PathAccess() expected to fail with \"%s\" but did not; err = \"%s\"", syscall.EACCES, err)
	}

	if err := PathAccess(mypid, filename, W_OK); err != syscall.EACCES {
		t.Fatalf("PathAccess() expected to fail with \"%s\" but did not; err = \"%s\"", syscall.EACCES, err)
	}

	// dir read-only
	if err := os.Chmod(filename, 0777); err != nil {
		t.Fatalf("failed to chmod test file: %v", err)
	}

	if err := os.Chmod(path, 0400); err != nil {
		t.Fatalf("failed to chmod test file: %v", err)
	}

	if err := PathAccess(mypid, filename, R_OK); err != syscall.EACCES {
		t.Fatalf("PathAccess() expected to fail with \"%s\" but did not; err = \"%s\"", syscall.EACCES, err)
	}
}

func TestPathAccessSymlink(t *testing.T) {

	mypid := os.Getpid()

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

	if err := PathAccess(mypid, link, R_OK|W_OK); err != nil {
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

	if err := PathAccess(mypid, "link", R_OK|W_OK); err != nil {
		t.Fatalf("PathAccess() failed: %v", err)
	}

	if err := os.Chdir(testCwd); err != nil {
		t.Fatalf("failed on os.Chdir(): %v", err)
	}

	// negative test on file perm

	if err := PathAccess(mypid, filename, X_OK); err != syscall.EACCES {
		t.Fatalf("PathAccess() expected to fail with \"%s\" but did not; err = \"%s\"", syscall.EACCES, err)
	}
}

// TODO:
// * test symlink resolution limit
// * test long path
