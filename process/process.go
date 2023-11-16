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

package process

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/nestybox/sysbox-fs/domain"
	cap "github.com/nestybox/sysbox-libs/capability"
	"github.com/nestybox/sysbox-runc/libcontainer/user"
	"golang.org/x/sys/unix"
	setxid "gopkg.in/hlandau/service.v1/daemon/setuid"

	"github.com/sirupsen/logrus"
)

type processService struct {
	ios domain.IOServiceIface
}

func NewProcessService() domain.ProcessServiceIface {
	return &processService{}
}

func (ps *processService) Setup(ios domain.IOServiceIface) {
	ps.ios = ios
}

func (ps *processService) ProcessCreate(
	pid uint32,
	uid uint32,
	gid uint32) domain.ProcessIface {

	return &process{
		pid: pid,
		uid: uid,
		gid: gid,
		ps:  ps,
	}
}

type process struct {
	pid         uint32                  // process id
	root        string                  // root dir
	procroot    string                  // proc's root string (/proc/<pid>/root)
	cwd         string                  // current working dir
	proccwd     string                  // proc's cwd string (/proc/<pid>/cwd)
	uid         uint32                  // effective uid
	gid         uint32                  // effective gid
	sgid        []uint32                // supplementary groups
	cap         cap.Capabilities        // process capabilities
	status      map[string]string       // process status fields
	nsInodes    map[string]domain.Inode // process namespace inodes
	initialized bool                    // process initialization completed
	ps          *processService         // pointer to parent processService
}

func (p *process) Pid() uint32 {

	if !p.initialized {
		p.init()
	}

	return p.pid
}

func (p *process) Uid() uint32 {

	if !p.initialized {
		p.init()
	}

	return p.uid
}

func (p *process) Gid() uint32 {

	if !p.initialized {
		p.init()
	}

	return p.gid
}

func (p *process) UidMap() ([]user.IDMap, error) {
	f := fmt.Sprintf("/proc/%d/uid_map", p.pid)
	return user.ParseIDMapFile(f)
}

func (p *process) GidMap() ([]user.IDMap, error) {
	f := fmt.Sprintf("/proc/%d/gid_map", p.pid)
	return user.ParseIDMapFile(f)
}

func (p *process) Cwd() string {

	if !p.initialized {
		p.init()
	}

	return p.cwd
}

func (p *process) Root() string {

	if !p.initialized {
		p.init()
	}

	return p.root
}

func (p *process) RootInode() uint64 {

	if !p.initialized {
		p.procroot = fmt.Sprintf("/proc/%d/root", p.pid)
	}

	return domain.FileInode(p.procroot)
}

func (p *process) SGid() []uint32 {

	if !p.initialized {
		p.init()
	}

	return p.sgid
}

func (p *process) IsSysAdminCapabilitySet() bool {
	return p.IsCapabilitySet(cap.EFFECTIVE, cap.CAP_SYS_ADMIN)
}

func (p *process) GetEffCaps() [2]uint32 {
	if p.cap == nil {
		if err := p.initCapability(); err != nil {
			return [2]uint32{0, 0}
		}
	}

	return p.cap.GetEffCaps()
}

func (p *process) SetEffCaps(caps [2]uint32) {
	if p.cap == nil {
		if err := p.initCapability(); err != nil {
			return
		}
	}

	p.cap.SetEffCaps(caps)
}

// Simple wrapper method to set capability values.
func (p *process) setCapability(which cap.CapType, what ...cap.Cap) {

	if p.cap == nil {
		if err := p.initCapability(); err != nil {
			return
		}
	}

	for _, elem := range what {
		p.cap.Set(which, elem)
	}
}

// Simple wrapper method to determine capability settings.
func (p *process) IsCapabilitySet(which cap.CapType, what cap.Cap) bool {

	if p.cap == nil {
		if err := p.initCapability(); err != nil {
			return false
		}
	}

	return p.cap.Get(which, what)
}

// initCapability method retrieves process capabilities from kernel and store
// them within 'capability' data-struct.
func (p *process) initCapability() error {

	c, err := cap.NewPid2(int(p.pid))
	if err != nil {
		return err
	}

	if err = c.Load(); err != nil {
		return err
	}

	p.cap = c

	return nil
}

// GetFd() returns a path to the file associated with a process' file descriptor.
func (p *process) GetFd(fd int32) (string, error) {
	fdlink := fmt.Sprintf("/proc/%d/fd/%d", p.pid, fd)
	return os.Readlink(fdlink)
}

// AdjustPersonality() method's purpose is to modify process' main attributes to
// match those of a secondary process. The main use-case is to allow sysbox-fs'
// nsexec logic to act on behalf of a user-triggered process.
func (p *process) AdjustPersonality(
	uid uint32,
	gid uint32,
	root string,
	cwd string,
	caps [2]uint32) error {

	if cwd != p.Cwd() {
		if err := unix.Chdir(cwd); err != nil {
			return err
		}
	}

	if root != p.Root() {
		if err := unix.Chroot(root); err != nil {
			return err
		}
	}

	if gid != p.Gid() {
		// Execute setresgid() syscall to set this process' effective gid.
		if err := setxid.Setresgid(-1, int(gid), -1); err != nil {
			return err
		}
	}

	if uid != p.Uid() {
		// Execute setresuid() syscall to set this process' effective uid.
		// Notice that as part of this instruction all effective capabilities of
		// the running process will be reset, which is something that we are looking
		// after given that "sysbox-fs nsenter" process runs with all capabilities
		// turned on. Further below we re-apply only those capabilities that were
		// present in the original process.
		if err := setxid.Setresuid(-1, int(uid), -1); err != nil {
			return err
		}
	}

	if caps != p.GetEffCaps() {
		// Set process' effective capabilities to match those passed by callee.
		p.cap.SetEffCaps(caps)
		if err := p.cap.Apply(
			cap.EFFECTIVE | cap.PERMITTED | cap.INHERITABLE); err != nil {
			return err
		}
	}

	return nil
}

func (p *process) NsInodes() (map[string]domain.Inode, error) {

	// First invocation causes the process ns inodes to be parsed
	if p.nsInodes == nil {
		nsInodes, err := p.GetNsInodes()
		if err != nil {
			return nil, err
		}
		p.nsInodes = nsInodes
	}

	return p.nsInodes, nil
}

func (p *process) MountNsInode() (domain.Inode, error) {
	nsInodes, err := p.NsInodes()
	if err != nil {
		return 0, err
	}

	mountns, found := nsInodes["mnt"]
	if !found {
		return 0, fmt.Errorf("mountns not found")
	}

	return mountns, nil
}

func (p *process) NetNsInode() (domain.Inode, error) {
	nsInodes, err := p.NsInodes()
	if err != nil {
		return 0, err
	}

	netns, found := nsInodes["net"]
	if !found {
		return 0, fmt.Errorf("netns not found")
	}

	return netns, nil
}

func (p *process) UserNsInode() (domain.Inode, error) {
	nsInodes, err := p.NsInodes()
	if err != nil {
		return 0, err
	}

	userns, found := nsInodes["user"]
	if !found {
		return 0, fmt.Errorf("userns not found")
	}

	return userns, nil
}

func (p *process) UserNsInodeParent() (domain.Inode, error) {

	// ioctl to retrieve the parent namespace.
	const NS_GET_PARENT = 0xb702

	usernsPath := filepath.Join(
		"/proc",
		strconv.FormatUint(uint64(p.pid), 10),
		"ns",
		"user",
	)

	// Open /proc/<pid>/ns/user to obtain a file-desc to refer to.
	childNsFd, err := os.Open(usernsPath)
	if err != nil {
		return 0, err
	}
	defer childNsFd.Close()

	// Launch ioctl to collect parent namespace fd.
	ret, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		childNsFd.Fd(),
		uintptr(NS_GET_PARENT),
		0)
	if errno != 0 {
		return 0, errno
	}
	parentNsFd := (int)((uintptr)(unsafe.Pointer(ret)))
	defer syscall.Close(parentNsFd)

	// Run stat() over the returned file descriptor to obtain the inode that
	// uniquely identifies the parent namespace.
	var stat syscall.Stat_t
	err = syscall.Fstat(parentNsFd, &stat)
	if err != nil {
		return 0, err
	}

	return stat.Ino, nil
}

// Collects the namespace inodes of the given process
func (p *process) GetNsInodes() (map[string]domain.Inode, error) {

	nsInodes := make(map[string]domain.Inode)
	pidStr := strconv.FormatUint(uint64(p.pid), 10)

	// Iterate through all namespaces to collect the process' namespace inodes.
	for _, ns := range domain.AllNSs {
		nsPath := filepath.Join("/proc", pidStr, "ns", ns)

		fnode := p.ps.ios.NewIOnode("", nsPath, 0)
		nsInode, err := fnode.GetNsInode()
		if err != nil {
			return nil, err
		}

		nsInodes[ns] = nsInode
	}

	return nsInodes, nil
}

// Exclusively utilized when dealing with memory file-systems during unit-testing.
// NsInodes are automatically created by kernel in regular scenarios.
func (p *process) CreateNsInodes(inode domain.Inode) error {

	pidStr := strconv.FormatUint(uint64(p.pid), 10)
	inodeStr := strconv.FormatUint(uint64(inode), 10)

	// Iterate through all namespaces to collect the process' namespace inodes.
	for _, ns := range domain.AllNSs {
		nsPath := filepath.Join("/proc", pidStr, "ns", ns)

		fnode := p.ps.ios.NewIOnode("", nsPath, 0)
		err := fnode.WriteFile([]byte(inodeStr))
		if err != nil {
			return err
		}
	}

	return nil
}

// UsernsRootUidGid returns the uid and gid for the root user in the user-ns associated
// with the process. If the user-ns has no mapping for the root user, the overflow
// uid & gid are returned (e.g., uid = gid = 65534).
func (p *process) UsernsRootUidGid() (uint32, uint32, error) {
	var (
		uid, gid uint32
		found    bool
		err      error
	)

	found = false
	uidMap, err := p.UidMap()
	if err == nil {
		for _, m := range uidMap {
			if m.ID == 0 {
				uid = uint32(m.ParentID)
				found = true
				break
			}
		}
	}

	if !found {
		uid, err = overflowUid()
		if err != nil {
			uid = 65534
		}
	}

	found = false
	gidMap, err := p.GidMap()
	if err == nil {
		for _, m := range gidMap {
			if m.ID == 0 {
				gid = uint32(m.ParentID)
				found = true
				break
			}
		}
	}

	if !found {
		gid, err = overflowGid()
		if err != nil {
			uid = 65534
		}
	}

	return uid, gid, nil
}

// PathAccess emulates the path resolution and permission checking process done by
// the Linux kernel, as described in path_resolution(7).
//
// It checks if the process with the given pid can access the file or directory at the
// given path.
//
// The given path may be absolute or relative. Each component of the path is checked to
// see if it exists and whether the process has permissions to access it, following the
// rules for path resolution in Linux (see path_resolution(7)). The path may contain ".",
// "..", and symlinks. For absolute paths, the check is done starting from the process'
// root directory. For relative paths, the check is done starting from the process'
// current working directory.
//
// The given mode determines what type of access to check for (e.g., read,
// write, execute, or a combination of these). If the mode is 0, this function checks
// if the process has execute/search permissions on all components of the path, but
// does not check access permissions on the the file itself.
//
// Returns nil if the process can access the path, or one of the following errors
// otherwise:
//
// syscall.ENOENT: some component of the path does not exist.
// syscall.ENOTDIR: a non-final component of the path is not a directory.
// syscall.EACCES: the process does not have permission to access at least one component of the path.
// syscall.ELOOP: the path too many symlinks (e.g. > 40).

func (p *process) PathAccess(path string, aMode domain.AccessMode, followSymlink bool) error {

	err := p.init()
	if err != nil {
		return err
	}

	path, err = p.ResolveProcSelf(path)
	if err != nil {
		return syscall.EINVAL
	}

	return p.pathAccess(path, aMode, followSymlink)
}

// init() retrieves info about the process to initialize its main attributes.
func (p *process) init() error {

	if p.initialized {
		return nil
	}

	space := regexp.MustCompile(`\s+`)

	fields := []string{"Uid", "Gid", "Groups"}
	if err := p.getStatus(fields); err != nil {
		return err
	}

	// effective uid
	str := space.ReplaceAllString(p.status["Uid"], " ")
	str = strings.TrimSpace(str)
	uids := strings.Split(str, " ")
	if len(uids) != 4 {
		return fmt.Errorf("invalid uid status: %+v", uids)
	}
	euid, err := strconv.Atoi(uids[1])
	if err != nil {
		return err
	}

	// effective gid
	str = space.ReplaceAllString(p.status["Gid"], " ")
	str = strings.TrimSpace(str)
	gids := strings.Split(str, " ")
	if len(gids) != 4 {
		return fmt.Errorf("invalid gid status: %+v", gids)
	}
	egid, err := strconv.Atoi(gids[1])
	if err != nil {
		return err
	}

	// supplementary groups
	sgid := []uint32{}
	str = space.ReplaceAllString(p.status["Groups"], " ")
	str = strings.TrimSpace(str)
	groups := strings.Split(str, " ")
	for _, g := range groups {
		if g == "" {
			continue
		}
		val, err := strconv.Atoi(g)
		if err != nil {
			return err
		}
		sgid = append(sgid, uint32(val))
	}

	// process root & cwd
	root := fmt.Sprintf("/proc/%d/root", p.pid)
	cwd := fmt.Sprintf("/proc/%d/cwd", p.pid)

	// process capabilities
	if p.cap == nil {
		if err := p.initCapability(); err != nil {
			return err
		}
	}

	// store all collected attributes
	p.root, _ = os.Readlink(root)
	p.cwd, _ = os.Readlink(cwd)
	p.procroot = root
	p.proccwd = cwd
	p.uid = uint32(euid)
	p.gid = uint32(egid)
	p.sgid = sgid

	// Mark process as fully initialized.
	p.initialized = true

	return nil
}

// getStatus retrieves process status info obtained from the
// /proc/[pid]/status file.
func (p *process) getStatus(fields []string) error {

	filename := fmt.Sprintf("/proc/%d/status", p.pid)
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	s := bufio.NewScanner(f)

	status := make(map[string]string)
	for s.Scan() {
		text := s.Text()
		parts := strings.Split(text, ":")

		if len(parts) < 1 {
			continue
		}

		for _, f := range fields {
			if parts[0] == f {
				if len(parts) > 1 {
					status[f] = parts[1]
				} else {
					status[f] = ""
				}
			}
		}
	}

	if err := s.Err(); err != nil {
		return err
	}

	p.status = status

	return nil
}

// Replaces the given path such as "/proc/self/*" with "/proc/<pid>/*", or
// "/proc/self/task/<tid>/*" with "/proc/<pid>/task/<tid>/*".
func replaceProcSelfWithProcPid(path string, pid uint32, tid uint32) string {
	var repl, p string

	pidMatch := regexp.MustCompile(`^/proc/self/(.*)`)
	tidMatch := regexp.MustCompile(`^/proc/self/task/[0-9]+/(.*)`)

	repl = fmt.Sprintf("/proc/self/task/%d/${1}", tid)
	p = tidMatch.ReplaceAllString(path, repl)

	repl = fmt.Sprintf("/proc/%d/${1}", pid)
	p = pidMatch.ReplaceAllString(p, repl)

	return p
}

// Given a path "/proc/self/path/to/symlink" it resolves it to the location
// pointed to by symlink. For example, if path is "/proc/self/fd/3" and
// "/proc/self/fd/3" is a symlink to "/some/path", then this function returns
// "/some/path". Note that "self" refers to the process struct, so we replace
// "self" with p.pid. The path resolution is recursive: E.g., if
// "/proc/self/fd/3" symlink points to "/proc/self/cwd", and "/proc/self/cwd"
// points to "/some/path", this function follows the symlinks and returns
// "/some/path".

func (p *process) ResolveProcSelf(path string) (string, error) {

	// NOTE: this function assumes procfs is mounted on /proc and path is
	// absolute.

	if !filepath.IsAbs(path) {
		return path, nil
	}

	if !strings.HasPrefix(path, "/proc/self/") {
		return path, nil
	}

	currPath := path
	linkCnt := 0

	for {
		if !strings.HasPrefix(currPath, "/proc/self/") {
			break
		}

		// Note: for paths such as /proc/self/task/<tid>/*, it's easy to replace
		// /proc/self with /proc/<pid> since we have the container's process pid
		// in sysbox's pid-namespace. However, that's not the case for the <tid>,
		// which is in the container's pid namespace and we have no good/easy way
		// to translate it sysbox's pid-ns. For now, assume that <tid> = <pid>.
		// It's not ideal, but it's normally the case when we receive such paths in
		// mount syscalls.

		tid := p.pid
		currPath = replaceProcSelfWithProcPid(currPath, p.pid, tid)

		fi, err := os.Lstat(currPath)
		if err != nil {
			return "", err
		}

		if fi.Mode()&os.ModeSymlink != os.ModeSymlink {
			break
		}

		linkCnt += 1
		if linkCnt > domain.SymlinkMax {
			logrus.Errorf("number of symlinks while resolving path %s exceeded the max allowed (40).", path)
			return "", syscall.ELOOP
		}

		// path starts with "/proc/self/" and it's a symlink, resolve it
		currPath, err = os.Readlink(currPath)
		if err != nil {
			return "", err
		}
	}

	return currPath, nil
}

func (p *process) pathAccess(path string, mode domain.AccessMode, followSymlink bool) error {

	if path == "" {
		return syscall.ENOENT
	}

	if len(path)+1 > syscall.PathMax {
		return syscall.ENAMETOOLONG
	}

	// Determine the start point.
	var start string
	if filepath.IsAbs(path) {
		start = p.procroot
	} else {
		start = p.proccwd
	}

	// Break up path into it's components; note that repeated "/" results in
	// empty path components.
	components := strings.Split(path, "/")

	cur := start
	linkCnt := 0
	final := false

	for i, c := range components {
		if i == len(components)-1 {
			final = true
		}

		if c == "" {
			continue
		}

		if c == ".." {
			parent := filepath.Dir(cur)
			if !strings.HasPrefix(parent, p.procroot) {
				parent = p.procroot
			}
			cur = parent
		} else if c != "." {
			cur = filepath.Join(cur, c)
		}

		symlink, isDir, err := isSymlink(cur)
		if err != nil {
			return syscall.ENOENT
		}

		if !final && !symlink && !isDir {
			return syscall.ENOTDIR
		}

		// Follow the symlink (unless it's the process root, or if it's the final
		// component of the path and followSymlink is false); may recurse if
		// symlink points to another symlink and so on; we stop at symlinkMax
		// recursions (just as the Linux kernel does).

		if !final || followSymlink {
			if symlink && cur != p.procroot {
				for {
					if linkCnt >= domain.SymlinkMax {
						return syscall.ELOOP
					}

					link, err := os.Readlink(cur)
					if err != nil {
						return syscall.ENOENT
					}

					if filepath.IsAbs(link) {
						cur = filepath.Join(p.procroot, link)
					} else {
						cur = filepath.Join(filepath.Dir(cur), link)
					}

					// If 'cur' ever matches 'p.procroot' then there's no need to continue
					// iterating as we know for sure that 'p.procroot' is a valid /
					// non-cyclical path. If we were to continue our iteration, we
					// would end up dereferencing 'p.procroot' -- through readlink() --
					// which would erroneously points us to "/" in the host fs.
					if cur == p.procroot {
						break
					}

					symlink, isDir, err = isSymlink(cur)
					if err != nil {
						return syscall.ENOENT
					}

					if !symlink {
						break
					}
					linkCnt += 1
				}

				if !final && !isDir {
					return syscall.ENOTDIR
				}
			}
		}

		perm := false
		if !final {
			perm, err = p.checkPerm(cur, domain.X_OK, followSymlink)
		} else {
			perm, err = p.checkPerm(cur, mode, followSymlink)
		}

		if err != nil || !perm {
			return syscall.EACCES
		}
	}

	return nil
}

// checkPerm checks if the given process has permission to access the file or
// directory at the given path. The access mode indicates what type of access is
// being checked (i.e., read, write, execute, or a combination of these). The
// given path must not be a symlink. Returns true if the given process has the
// required permission, false otherwise. The returned error indicates if an
// error occurred during the check.
func (p *process) checkPerm(path string, aMode domain.AccessMode, followSymlink bool) (bool, error) {
	var (
		fi  os.FileInfo
		err error
	)

	if followSymlink {
		fi, err = os.Stat(path)
	} else {
		fi, err = os.Lstat(path)
	}

	if err != nil {
		return false, err
	}

	fperm := fi.Mode().Perm()

	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false, fmt.Errorf("failed to convert to syscall.Stat_t")
	}
	fuid := st.Uid
	fgid := st.Gid

	mode := uint32(aMode)

	// no access = permission granted
	if mode == 0 {
		return true, nil
	}

	// Note: the order of the checks below mimics those done by the Linux kernel.

	// owner check
	if fuid == p.uid {
		perm := uint32((fperm & 0700) >> 6)
		if mode&perm == mode {
			return true, nil
		}
	}

	// group check
	if fgid == p.gid || uint32SliceContains(p.sgid, fgid) {
		perm := uint32((fperm & 0070) >> 3)
		if mode&perm == mode {
			return true, nil
		}
	}

	// "other" check
	perm := uint32(fperm & 0007)
	if mode&perm == mode {
		return true, nil
	}

	// capability checks
	if p.IsCapabilitySet(cap.EFFECTIVE, cap.CAP_DAC_OVERRIDE) {
		// Per capabilitis(7): CAP_DAC_OVERRIDE bypasses file read, write,
		// and execute permission checks.
		//
		// Per The Linux Programming Interface, 15.4.3: A process with the
		// CAP_DAC_OVERRIDE capability always has read and write permissions
		// for any type of file, and also has execute permission if the file
		// is a directory or if execute permission is granted to at least one
		// of the permission categories for the file.
		if fi.IsDir() {
			return true, nil
		} else {
			if aMode&domain.X_OK != domain.X_OK {
				return true, nil
			} else {
				if fperm&0111 != 0 {
					return true, nil
				}
			}
		}
	}

	if p.IsCapabilitySet(cap.EFFECTIVE, cap.CAP_DAC_READ_SEARCH) {
		// Per capabilities(7): CAP_DAC_READ_SEARCH bypasses file read permission
		// checks and directory read and execute permission checks
		if fi.IsDir() && (aMode&domain.W_OK != domain.W_OK) {
			return true, nil
		}

		if !fi.IsDir() && (aMode == domain.R_OK) {
			return true, nil
		}
	}

	return false, nil
}

//
// Miscellaneous auxiliary functions
//

// isSymlink returns true if the given file is a symlink
func isSymlink(path string) (bool, bool, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return false, false, err
	}

	return fi.Mode()&os.ModeSymlink == os.ModeSymlink, fi.IsDir(), nil
}

// uint32SliceContains returns true if x is in a
func uint32SliceContains(a []uint32, x uint32) bool {
	for _, n := range a {
		if x == n {
			return true
		}
	}
	return false
}

func readOverflowID(path string) (uint32, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	str, err := bufio.NewReader(f).ReadString('\n')
	if err != nil {
		return 0, err
	}
	str = strings.Trim(str, "\n")

	val, err := strconv.Atoi(str)
	if err != nil {
		return 0, err
	}

	return uint32(val), nil
}

func overflowUid() (uint32, error) {
	return readOverflowID("/proc/sys/fs/overflowuid")
}

func overflowGid() (uint32, error) {
	return readOverflowID("/proc/sys/fs/overflowgid")
}
