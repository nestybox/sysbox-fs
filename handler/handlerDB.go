package handler

import (
	"errors"
	"os"
	"path"
	"strconv"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysvisor-fs/domain"
	"github.com/nestybox/sysvisor-fs/handler/implementations"
)

//
// Slice of sysvisor-fs' default handlers. Please keep me alphabetically
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
		Enabled:   true,
		Cacheable: true,
	},
	&implementations.ProcCgroupsHandler{
		Name:      "procCgroups",
		Path:      "/proc/cgroups",
		Enabled:   true,
		Cacheable: false,
	},
	&implementations.ProcCpuinfoHandler{
		Name:      "procCpuinfo",
		Path:      "/proc/cpuinfo",
		Enabled:   true,
		Cacheable: true,
	},
	&implementations.ProcDevicesHandler{
		Name:      "procDevices",
		Path:      "/proc/devices",
		Enabled:   true,
		Cacheable: false,
	},
	&implementations.ProcDiskstatsHandler{
		Name:      "procDiskstats",
		Path:      "/proc/diskstats",
		Enabled:   true,
		Cacheable: false,
	},
	&implementations.ProcLoadavgHandler{
		Name:      "procLoadavg",
		Path:      "/proc/loadavg",
		Enabled:   true,
		Cacheable: false,
	},
	&implementations.ProcMeminfoHandler{
		Name:      "procMeminfo",
		Path:      "/proc/meminfo",
		Enabled:   true,
		Cacheable: false,
	},
	&implementations.ProcPagetypeinfoHandler{
		Name:      "procPagetypeinfo",
		Path:      "/proc/pagetypeinfo",
		Enabled:   true,
		Cacheable: false,
	},
	&implementations.ProcPartitionsHandler{
		Name:      "procPartitions",
		Path:      "/proc/partitions",
		Enabled:   true,
		Cacheable: false,
	},
	&implementations.ProcStatHandler{
		Name:      "procStat",
		Path:      "/proc/stat",
		Enabled:   true,
		Cacheable: false,
	},
	&implementations.ProcSwapsHandler{
		Name:      "procSwaps",
		Path:      "/proc/swaps",
		Enabled:   true,
		Cacheable: false,
	},
	&implementations.ProcSysHandler{
		Name:      "procSys",
		Path:      "/proc/sys",
		Enabled:   true,
		Cacheable: false,
	},
	&implementations.ProcUptimeHandler{
		Name:      "procUptime",
		Path:      "/proc/uptime",
		Enabled:   true,
		Cacheable: false,
	},
	//
	// /proc/sys/net/netfilter handlers
	&implementations.NfConntrackMaxHandler{
		Name:      "nfConntrackMax",
		Path:      "/proc/sys/net/netfilter/nf_conntrack_max",
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
	css domain.ContainerStateService

	// Pointer to the service providing nsenter (rexec) capabilities.
	nss domain.NSenterService

	// Pointer to the service providing file-system I/O capabilities.
	ios domain.IOService

	// Represents the pid-namespace inode of the host's true-root.
	hostPidInode domain.Inode
}

// HandlerService constructor.
func NewHandlerService(
	hs []domain.HandlerIface,
	css domain.ContainerStateService,
	nss domain.NSenterService,
	ios domain.IOService) domain.HandlerService {

	newhs := &handlerService{
		handlerDB:     make(map[string]domain.HandlerIface),
		dirHandlerMap: make(map[string][]string),
		css:           css,
		nss:           nss,
		ios:           ios,
	}

	// Register all handlers declared as 'enabled'.
	for _, h := range hs {
		if h.GetEnabled() {
			newhs.RegisterHandler(h)
		}
	}

	// Create a directory-handler map to keep track of the associattion between
	// emulated resource paths, and the parent directory hosting them.
	newhs.createDirHandlerMap()

	newhs.hostPidInode = newhs.FindPidNsInode(uint32(os.Getpid()))

	return newhs
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

func (hs *handlerService) LookupHandler(i domain.IOnode) (domain.HandlerIface, bool) {

	hs.RLock()
	defer hs.RUnlock()

	h, ok := hs.handlerDB[i.Path()]
	if !ok {
		h, ok := hs.handlerDB["commonHandler"]
		if !ok {
			return nil, false
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

func (hs *handlerService) StateService() domain.ContainerStateService {
	return hs.css
}

func (hs *handlerService) NSenterService() domain.NSenterService {
	return hs.nss
}

func (hs *handlerService) IOService() domain.IOService {
	return hs.ios
}

//
// Auxiliar methods
//
func (hs *handlerService) HostPidNsInode() domain.Inode {
	return hs.hostPidInode
}

func (hs *handlerService) FindPidNsInode(pid uint32) domain.Inode {

	//tmpNode := hs.ios.NewIOnode("", strconv.Itoa(pid), 0)
	tmpNode := hs.ios.NewIOnode("", strconv.FormatUint(uint64(pid), 10), 0)
	pidInode, err := hs.ios.PidNsInode(tmpNode)
	if err != nil {
		return 0
	}

	return pidInode
}
