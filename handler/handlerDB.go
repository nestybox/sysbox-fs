package handler

import (
	"errors"
	"log"
	"sync"

	"github.com/nestybox/sysvisor/sysvisor-fs/domain"
	"github.com/nestybox/sysvisor/sysvisor-fs/handler/implementations"
)

var DefaultHandlers = []domain.HandlerIface{
	&implementations.ProcCgroupsHandler{
		Name:    "procCgroups",
		Path:    "/proc/cgroups",
		Enabled: false,
	},
	&implementations.ProcLoadavgHandler{
		Name:    "procLoadavg",
		Path:    "/proc/laodavg",
		Enabled: false,
	},
	&implementations.ProcMeminfoHandler{
		Name:    "procMeminfo",
		Path:    "/proc/meminfo",
		Enabled: false,
	},
	&implementations.ProcPagetypeinfoHandler{
		Name:    "procPagetypeinfo",
		Path:    "/proc/pagetypeinfo",
		Enabled: false,
	},
	&implementations.ProcPartitionsHandler{
		Name:    "procPartitions",
		Path:    "/proc/partitions",
		Enabled: false,
	},
	&implementations.ProcStatHandler{
		Name:    "procStat",
		Path:    "/proc/stat",
		Enabled: false,
	},
	&implementations.ProcSwapsHandler{
		Name:    "procSwaps",
		Path:    "/proc/swaps",
		Enabled: false,
	},
	&implementations.ProcSysHandler{
		Name:    "procSys",
		Path:    "/proc/sys",
		Enabled: false,
	},
	&implementations.ProcUptimeHandler{
		Name:    "procUptime",
		Path:    "/proc/uptime",
		Enabled: true,
	},
	&implementations.NfConntrackMaxHandler{
		Name:    "nfConntrackMax",
		Path:    "/proc/sys/net/netfilter/nf_conntrack_max",
		Enabled: true,
	},
	&implementations.DisableIPv6Handler{
		Name:    "disableIPv6",
		Path:    "/proc/sys/net/ipv6/conf/all/disable_ipv6",
		Enabled: true,
	},
	// &domain.Handler{
	// 	Name:    "nfCallIptable",
	// 	Path:    "/proc/sys/net/bridge/bridge-nf-call-iptables",
	// 	Enabled: true,
	// },
	// &domain.Handler{
	// 	Name:    "routeLocalnet",
	// 	Path:    "/proc/sys/net/ipv4/conf/all/route_localnet",
	// 	Enabled: true,
	// },
	// &domain.Handler{
	// 	Name:    "panic",
	// 	Path:    "/proc/sys/kernel/panic",
	// 	Enabled: true,
	// },
	// &domain.Handler{
	// 	Name:    "panicOops",
	// 	Path:    "/proc/sys/kernel/panic_on_oops",
	// 	Enabled: true,
	// },
	// &domain.Handler{
	// 	Name:    "overcommitMemory",
	// 	Path:    "/proc/sys/vm/overcommit_memory",
	// 	Enabled: true,
	// },
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

func (hs *handlerService) LookupHandler(name string) (domain.HandlerIface, bool) {
	hs.RLock()
	defer hs.RUnlock()

	h, ok := hs.handlerDB[name]
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
