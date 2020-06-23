//
// Copyright: (C) 2019-2020 Nestybox Inc.  All rights reserved.
//

package handler

import (
	"errors"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/handler/implementations"
)

//
// Slice of sysbox-fs' default handlers. Please keep me alphabetically
// ordered within each functional bucket.
//
var DefaultHandlers = []domain.HandlerIface{
	//
	// / handler
	//
	&implementations.RootHandler{
		Name:      "root",
		Path:      "/",
		Enabled:   true,
		Cacheable: true,
	},
	//
	// /proc handlers
	//
	&implementations.ProcHandler{
		Name:      "proc",
		Path:      "/proc",
		Type:      domain.NODE_MOUNT,
		Enabled:   true,
		Cacheable: true,
	},
	&implementations.ProcCgroupsHandler{
		Name:      "procCgroups",
		Path:      "/proc/cgroups",
		Type:      domain.NODE_SUBSTITUTION | domain.NODE_BINDMOUNT,
		Enabled:   true,
		Cacheable: false,
	},
	&implementations.ProcCpuinfoHandler{
		Name:      "procCpuinfo",
		Path:      "/proc/cpuinfo",
		Type:      domain.NODE_SUBSTITUTION | domain.NODE_BINDMOUNT,
		Enabled:   true,
		Cacheable: true,
	},
	&implementations.ProcDevicesHandler{
		Name:      "procDevices",
		Path:      "/proc/devices",
		Type:      domain.NODE_SUBSTITUTION | domain.NODE_BINDMOUNT,
		Enabled:   true,
		Cacheable: false,
	},
	&implementations.ProcDiskstatsHandler{
		Name:      "procDiskstats",
		Path:      "/proc/diskstats",
		Type:      domain.NODE_SUBSTITUTION | domain.NODE_BINDMOUNT,
		Enabled:   true,
		Cacheable: false,
	},
	&implementations.ProcLoadavgHandler{
		Name:      "procLoadavg",
		Path:      "/proc/loadavg",
		Type:      domain.NODE_SUBSTITUTION | domain.NODE_BINDMOUNT,
		Enabled:   true,
		Cacheable: false,
	},
	&implementations.ProcMeminfoHandler{
		Name:      "procMeminfo",
		Path:      "/proc/meminfo",
		Type:      domain.NODE_SUBSTITUTION | domain.NODE_BINDMOUNT,
		Enabled:   true,
		Cacheable: false,
	},
	&implementations.ProcPagetypeinfoHandler{
		Name:      "procPagetypeinfo",
		Path:      "/proc/pagetypeinfo",
		Type:      domain.NODE_SUBSTITUTION | domain.NODE_BINDMOUNT,
		Enabled:   true,
		Cacheable: false,
	},
	&implementations.ProcPartitionsHandler{
		Name:      "procPartitions",
		Path:      "/proc/partitions",
		Type:      domain.NODE_SUBSTITUTION | domain.NODE_BINDMOUNT,
		Enabled:   true,
		Cacheable: false,
	},
	&implementations.ProcStatHandler{
		Name:      "procStat",
		Path:      "/proc/stat",
		Type:      domain.NODE_SUBSTITUTION | domain.NODE_BINDMOUNT,
		Enabled:   true,
		Cacheable: false,
	},
	&implementations.ProcSwapsHandler{
		Name:      "procSwaps",
		Path:      "/proc/swaps",
		Type:      domain.NODE_SUBSTITUTION | domain.NODE_BINDMOUNT | domain.NODE_PROPAGATE,
		Enabled:   true,
		Cacheable: false,
	},
	&implementations.ProcSysHandler{
		Name:      "procSys",
		Path:      "/proc/sys",
		Type:      domain.NODE_SUBSTITUTION | domain.NODE_BINDMOUNT | domain.NODE_PROPAGATE,
		Enabled:   true,
		Cacheable: false,
	},
	&implementations.ProcUptimeHandler{
		Name:      "procUptime",
		Path:      "/proc/uptime",
		Type:      domain.NODE_SUBSTITUTION | domain.NODE_BINDMOUNT | domain.NODE_PROPAGATE,
		Enabled:   true,
		Cacheable: false,
	},
	//
	// /proc/sys/fs handlers
	//
	&implementations.FsBinfmtHandler{
		Name:      "fsBinfmt",
		Path:      "/proc/sys/fs/binfmt_misc",
		Type:      domain.NODE_SUBSTITUTION,
		Enabled:   true,
		Cacheable: false,
	},
	&implementations.FsBinfmtStatusHandler{
		Name:      "fsBinfmtStatus",
		Path:      "/proc/sys/fs/binfmt_misc/status",
		Type:      domain.NODE_SUBSTITUTION,
		Enabled:   true,
		Cacheable: false,
	},
	&implementations.FsBinfmtRegisterHandler{
		Name:      "fsBinfmtRegister",
		Path:      "/proc/sys/fs/binfmt_misc/register",
		Type:      domain.NODE_SUBSTITUTION,
		Enabled:   true,
		Cacheable: false,
	},
	&implementations.FsProtectHardLinksHandler{
		Name:      "fsProtectHardLinks",
		Path:      "/proc/sys/fs/protected_hardlinks",
		Type:      domain.NODE_SUBSTITUTION,
		Enabled:   true,
		Cacheable: true,
	},
	&implementations.FsProtectSymLinksHandler{
		Name:      "fsProtectSymLinks",
		Path:      "/proc/sys/fs/protected_symlinks",
		Type:      domain.NODE_SUBSTITUTION,
		Enabled:   true,
		Cacheable: true,
	},
	//
	// /proc/sys/kernel handlers
	//
	&implementations.KernelKptrRestrictHandler{
		Name:      "kernelKptrRestrict",
		Path:      "/proc/sys/kernel/kptr_restrict",
		Type:      domain.NODE_SUBSTITUTION,
		Enabled:   true,
		Cacheable: true,
	},
	&implementations.KernelNgroupsMaxHandler{
		Name:      "kernelNgroupsMax",
		Path:      "/proc/sys/kernel/ngroups_max",
		Type:      domain.NODE_SUBSTITUTION,
		Enabled:   true,
		Cacheable: true,
	},
	&implementations.KernelLastCapHandler{
		Name:      "kernelLastCap",
		Path:      "/proc/sys/kernel/cap_last_cap",
		Type:      domain.NODE_SUBSTITUTION,
		Enabled:   true,
		Cacheable: true,
	},
	&implementations.KernelPanicHandler{
		Name:      "kernelPanic",
		Path:      "/proc/sys/kernel/panic",
		Type:      domain.NODE_SUBSTITUTION,
		Enabled:   true,
		Cacheable: true,
	},
	&implementations.KernelPanicOopsHandler{
		Name:      "kernelPanicOops",
		Path:      "/proc/sys/kernel/panic_on_oops",
		Type:      domain.NODE_SUBSTITUTION,
		Enabled:   true,
		Cacheable: true,
	},
	&implementations.KernelPrintkHandler{
		Name:      "kernelPrintk",
		Path:      "/proc/sys/kernel/printk",
		Type:      domain.NODE_SUBSTITUTION,
		Enabled:   true,
		Cacheable: true,
	},
	&implementations.KernelSysrqHandler{
		Name:      "kernelSysrq",
		Path:      "/proc/sys/kernel/sysrq",
		Type:      domain.NODE_SUBSTITUTION,
		Enabled:   true,
		Cacheable: true,
	},
	&implementations.KernelYamaPtraceScopeHandler{
		Name:      "kernelYamaPtraceScope",
		Path:      "/proc/sys/kernel/yama/ptrace_scope",
		Type:      domain.NODE_SUBSTITUTION,
		Enabled:   true,
		Cacheable: true,
	},
	//
	// /proc/sys/net/core handlers
	//
	&implementations.CoreDefaultQdiscHandler{
		Name:      "coreDefaultQdisc",
		Path:      "/proc/sys/net/core/default_qdisc",
		Type:      domain.NODE_SUBSTITUTION,
		Enabled:   true,
		Cacheable: true,
	},
	//
	// /proc/sys/net/netfilter handlers
	//
	&implementations.NfConntrackMaxHandler{
		Name:      "nfConntrackMax",
		Path:      "/proc/sys/net/netfilter/nf_conntrack_max",
		Type:      domain.NODE_SUBSTITUTION,
		Enabled:   true,
		Cacheable: true,
	},
	&implementations.NfConntrackTcpTimeoutEstHandler{
		Name:      "nfConntrackTcpTimeoutEst",
		Path:      "/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established",
		Type:      domain.NODE_SUBSTITUTION,
		Enabled:   true,
		Cacheable: true,
	},
	&implementations.NfConntrackTcpTimeoutCWaitHandler{
		Name:      "nfConntrackTcpTimeoutCWait",
		Path:      "/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_close_wait",
		Type:      domain.NODE_SUBSTITUTION,
		Enabled:   true,
		Cacheable: true,
	},
	//
	// /proc/sys/net/ipv4/vs handlers
	//
	&implementations.VsConntrackHandler{
		Name:      "vsConntrack",
		Path:      "/proc/sys/net/ipv4/vs/conntrack",
		Type:      domain.NODE_SUBSTITUTION,
		Enabled:   true,
		Cacheable: true,
	},
	&implementations.VsConnReuseModeHandler{
		Name:      "vsConnReuseMode",
		Path:      "/proc/sys/net/ipv4/vs/conn_reuse_mode",
		Type:      domain.NODE_SUBSTITUTION,
		Enabled:   true,
		Cacheable: true,
	},
	&implementations.VsExpireNoDestConnHandler{
		Name:      "vsExpireNoDestConn",
		Path:      "/proc/sys/net/ipv4/vs/expire_nodest_conn",
		Type:      domain.NODE_SUBSTITUTION,
		Enabled:   true,
		Cacheable: true,
	},
	&implementations.VsExpireQuiescentTemplateHandler{
		Name:      "vsExpireQuiescentTemplate",
		Path:      "/proc/sys/net/ipv4/vs/expire_quiescent_template",
		Type:      domain.NODE_SUBSTITUTION,
		Enabled:   true,
		Cacheable: true,
	},
	//
	// /proc/sys/net/unix handlers
	//
	&implementations.MaxDgramQlenHandler{
		Name:      "maxDgramQlen",
		Path:      "/proc/sys/net/unix/max_dgram_qlen",
		Type:      domain.NODE_SUBSTITUTION,
		Enabled:   true,
		Cacheable: true,
	},
	//
	// /proc/sys/vm handlers
	//
	&implementations.VmOvercommitMemHandler{
		Name:      "vmOvercommitMem",
		Path:      "/proc/sys/vm/overcommit_memory",
		Type:      domain.NODE_SUBSTITUTION,
		Enabled:   true,
		Cacheable: true,
	},
	&implementations.VmMmapMinAddrHandler{
		Name:      "vmMmapMinAddr",
		Path:      "/proc/sys/vm/mmap_min_addr",
		Type:      domain.NODE_SUBSTITUTION,
		Enabled:   true,
		Cacheable: true,
	},
	//
	// /sys handlers
	//
	&implementations.SysHandler{
		Name:      "sys",
		Path:      "/sys",
		Type:      domain.NODE_MOUNT,
		Enabled:   false,
		Cacheable: true,
	},
	&implementations.NfConntrackHashSizeHandler{
		Name:      "nfConntrackHashSize",
		Path:      "/sys/module/nf_conntrack/parameters/hashsize",
		Type:      domain.NODE_SUBSTITUTION | domain.NODE_BINDMOUNT | domain.NODE_PROPAGATE,
		Enabled:   true,
		Cacheable: true,
	},
	//
	// Common handler -- to be utilized for all namespaced resources.
	//
	&implementations.CommonHandler{
		Name:      "common",
		Path:      "commonHandler",
		Enabled:   true,
		Cacheable: true,
	},
	//
	// SysCommon handler -- to be utilized for all namespaced resources.
	//
	&implementations.SysCommonHandler{
		Name:      "sysCommon",
		Path:      "sysCommonHandler",
		Enabled:   true,
		Cacheable: false,
	},
	//
	// Testing handler
	//
	&implementations.TestingHandler{
		Name:      "testing",
		Path:      "/testing",
		Enabled:   true,
		Cacheable: false,
	},
}

type handlerService struct {
	sync.RWMutex

	// Map to store association between handler's path (key) and the handler
	// object (value).
	handlerDB map[string]domain.HandlerIface

	// Map to keep track of the resources being emulated and the directory where
	// these are being placed. Map is indexed by directory path (string), and
	// the value corresponds to a slice of strings that holds the full path of
	// the emulated resources seating in each directory.
	dirHandlerMap map[string][]string

	// Pointer to the service providing container-state storage functionality.
	css domain.ContainerStateServiceIface

	// Pointer to the service providing nsenter (rexec) capabilities.
	nss domain.NSenterServiceIface

	// Pointer to the service providing process-handling functionality.
	prs domain.ProcessServiceIface

	// Pointer to the service providing file-system I/O capabilities.
	ios domain.IOServiceIface

	// Represents the user-namespace inode of the host's true-root.
	hostUserNsInode domain.Inode

	// Handler i/o errors should be obviated if this flag is enabled (testing
	// purposes).
	ignoreErrors bool
}

// HandlerService constructor.
func NewHandlerService() domain.HandlerServiceIface {

	newhs := &handlerService{
		handlerDB:     make(map[string]domain.HandlerIface),
		dirHandlerMap: make(map[string][]string),
	}

	return newhs
}

func (hs *handlerService) Setup(
	hdlrs []domain.HandlerIface,
	ignoreErrors bool,
	css domain.ContainerStateServiceIface,
	nss domain.NSenterServiceIface,
	prs domain.ProcessServiceIface,
	ios domain.IOServiceIface) {

	hs.css = css
	hs.nss = nss
	hs.prs = prs
	hs.ios = ios
	hs.ignoreErrors = ignoreErrors

	// Register all handlers declared as 'enabled'.
	for _, h := range hdlrs {
		if h.GetEnabled() {
			hs.RegisterHandler(h)
		}
	}

	// Create a directory-handler map to keep track of the association between
	// emulated resource paths, and the parent directory hosting them.
	hs.createDirHandlerMap()

	// Obtain user-ns inode corresponding to the host fs (root user-ns).
	hostUserNsInode, err := hs.FindUserNsInode(uint32(os.Getpid()))
	if err != nil {
		logrus.Fatalf("Invalid init user-namespace found")
	}
	hs.hostUserNsInode = hostUserNsInode
}

func (hs *handlerService) createDirHandlerMap() {
	hs.Lock()
	defer hs.Unlock()

	var dirHandlerMap = hs.dirHandlerMap

	// Iterate through all the registered handlers to populate the dirHandlerMap
	// structure. Even though this is an O(n^2) logic, notice that 'n' here is
	// very small (number of handlers), and that this is only executed during
	// process initialization.
	for h1, _ := range hs.handlerDB {
		dir_h1 := path.Dir(h1)

		for h2, _ := range hs.handlerDB {
			dir_h2 := path.Dir(h2)

			// A potential handler candidate must fully match the dir-path of
			// the original one.
			if dir_h1 == dir_h2 {
				var dup = false
				dirHandlerMapSlice := dirHandlerMap[dir_h1]

				// Avoid pushing duplicated elements into any given slice.
				for _, elem := range dirHandlerMapSlice {
					if elem == h1 {
						dup = true
						break
					}
				}

				// Proceed to push a new entry if no dups have been encountered.
				if !dup {
					dirHandlerMapSlice = append(dirHandlerMapSlice, h1)
					dirHandlerMap[dir_h1] = dirHandlerMapSlice
				}
			}
		}
	}

	hs.dirHandlerMap = dirHandlerMap
}

func (hs *handlerService) RegisterHandler(h domain.HandlerIface) error {
	hs.Lock()

	name := h.GetName()
	path := h.GetPath()

	if _, ok := hs.handlerDB[path]; ok {
		hs.Unlock()
		logrus.Errorf("Handler %v already registered", name)
		return errors.New("Handler already registered")
	}

	h.SetService(hs)
	hs.handlerDB[path] = h
	hs.Unlock()

	return nil
}

func (hs *handlerService) UnregisterHandler(h domain.HandlerIface) error {
	hs.Lock()

	name := h.GetName()
	path := h.GetPath()

	if _, ok := hs.handlerDB[path]; !ok {
		hs.Unlock()
		logrus.Errorf("Handler %v not previously registered", name)
		return errors.New("Handler not previously registered")
	}

	delete(hs.handlerDB, name)
	hs.Unlock()

	return nil
}

func (hs *handlerService) LookupHandler(
	i domain.IOnodeIface) (domain.HandlerIface, bool) {

	hs.RLock()
	defer hs.RUnlock()

	h, ok := hs.handlerDB[i.Path()]
	if !ok {
		if strings.HasPrefix(i.Path(), "/sys") {
			h, ok = hs.handlerDB["sysCommonHandler"]
			if !ok {
				return nil, false
			}
		} else {
			h, ok = hs.handlerDB["commonHandler"]
			if !ok {
				return nil, false
			}
		}

		return h, true
	}

	return h, true
}

func (hs *handlerService) FindHandler(s string) (domain.HandlerIface, bool) {

	hs.RLock()
	defer hs.RUnlock()

	h, ok := hs.handlerDB[s]
	if !ok {
		return nil, false
	}

	return h, true
}

func (hs *handlerService) EnableHandler(h domain.HandlerIface) error {
	hs.Lock()

	name := h.GetName()
	path := h.GetPath()

	if _, ok := hs.handlerDB[path]; !ok {
		hs.Unlock()
		logrus.Errorf("Handler %v not found", name)
		return errors.New("Handler not found")
	}

	h.SetEnabled(true)
	hs.Unlock()

	return nil
}

func (hs *handlerService) DisableHandler(h domain.HandlerIface) error {
	hs.Lock()

	name := h.GetName()
	path := h.GetPath()

	if _, ok := hs.handlerDB[path]; !ok {
		hs.Unlock()
		logrus.Errorf("Handler %v not found", name)
		return errors.New("Handler not found")
	}

	h.SetEnabled(false)
	hs.Unlock()

	return nil
}

func (hs *handlerService) DirHandlerEntries(s string) []string {
	hs.RLock()
	defer hs.RUnlock()

	return hs.dirHandlerMap[s]
}

func (hs *handlerService) HandlerDB() map[string]domain.HandlerIface {
	return hs.handlerDB
}

func (hs *handlerService) StateService() domain.ContainerStateServiceIface {
	return hs.css
}

func (hs *handlerService) SetStateService(css domain.ContainerStateServiceIface) {
	hs.css = css
}

func (hs *handlerService) NSenterService() domain.NSenterServiceIface {
	return hs.nss
}

func (hs *handlerService) ProcessService() domain.ProcessServiceIface {
	return hs.prs
}

func (hs *handlerService) IOService() domain.IOServiceIface {
	return hs.ios
}

func (hs *handlerService) IgnoreErrors() bool {
	return hs.ignoreErrors
}

//
// Auxiliary methods
//

func (hs *handlerService) HostUserNsInode() domain.Inode {
	return hs.hostUserNsInode
}

func (hs *handlerService) FindUserNsInode(pid uint32) (domain.Inode, error) {
	process := hs.prs.ProcessCreate(pid, 0, 0)

	userNsInode, err := process.UserNsInode()
	if err != nil {
		return 0, err
	}

	return userNsInode, nil
}
