package handler

import (
	"errors"
	"log"
	"sync"

	"github.com/nestybox/sysvisor/sysvisor-fs/domain"
	"github.com/nestybox/sysvisor/sysvisor-fs/handler/implementations"
)

//
// Slice of sysvisor-fs' default handlers. Please keep me alphabetically
// ordered within each functional bucket.
//
var DefaultHandlers = []domain.HandlerIface{
	//
	// /proc handlers
	//
	&implementations.ProcCgroupsHandler{
		Name:      "procCgroups",
		Path:      "/proc/cgroups",
		Enabled:   false,
		Cacheable: false,
	},
	&implementations.ProcLoadavgHandler{
		Name:      "procLoadavg",
		Path:      "/proc/laodavg",
		Enabled:   false,
		Cacheable: false,
	},
	&implementations.ProcMeminfoHandler{
		Name:      "procMeminfo",
		Path:      "/proc/meminfo",
		Enabled:   false,
		Cacheable: false,
	},
	&implementations.ProcPagetypeinfoHandler{
		Name:      "procPagetypeinfo",
		Path:      "/proc/pagetypeinfo",
		Enabled:   false,
		Cacheable: false,
	},
	&implementations.ProcPartitionsHandler{
		Name:      "procPartitions",
		Path:      "/proc/partitions",
		Enabled:   false,
		Cacheable: false,
	},
	&implementations.ProcStatHandler{
		Name:      "procStat",
		Path:      "/proc/stat",
		Enabled:   false,
		Cacheable: false,
	},
	&implementations.ProcSwapsHandler{
		Name:      "procSwaps",
		Path:      "/proc/swaps",
		Enabled:   false,
		Cacheable: false,
	},
	&implementations.ProcSysHandler{
		Name:      "procSys",
		Path:      "/proc/sys",
		Enabled:   false,
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
	//
	&implementations.NetNetfilter{
		Name:      "netNetfilter",
		Path:      "/proc/sys/net/netfilter",
		Enabled:   true,
		Cacheable: false,
	},
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
	handlerDB map[string]domain.HandlerIface
	css       domain.ContainerStateService
}

func NewHandlerService(
	hs []domain.HandlerIface,
	css domain.ContainerStateService) domain.HandlerService {

	newhs := &handlerService{
		handlerDB: make(map[string]domain.HandlerIface),
		css:       css,
	}

	// Register all handlers declared as 'enabled'.
	for _, h := range hs {
		if h.GetEnabled() {
			newhs.RegisterHandler(h)
		}
	}

	return newhs
}

func (hs *handlerService) RegisterHandler(h domain.HandlerIface) error {
	hs.Lock()

	name := h.GetName()
	path := h.GetPath()

	if _, ok := hs.handlerDB[path]; ok {
		hs.Unlock()
		log.Printf("Handler %v already registered\n", name)
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
		log.Printf("Handler %v not previously registered\n", name)
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

func (hs *handlerService) EnableHandler(h domain.HandlerIface) error {
	hs.Lock()

	name := h.GetName()
	path := h.GetPath()

	if _, ok := hs.handlerDB[path]; !ok {
		hs.Unlock()
		log.Printf("Handler %v not found\n", name)
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
		log.Printf("Handler %v not found\n", name)
		return errors.New("Handler not found")
	}

	h.SetEnabled(false)
	hs.Unlock()

	return nil
}

func (hs *handlerService) StateService() domain.ContainerStateService {
	return hs.css
}
