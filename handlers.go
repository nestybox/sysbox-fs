package main

import (
	"errors"
	"io"
	"log"
	"strconv"
	"strings"
	"time"

	"bazil.org/fuse"
)

// HandlerMap alias
type handlerMap = map[string]handler

//
// Handler interface.
//
type handler interface {
	onOpen(cs *containerState, flags fuse.OpenFlags) error
	onRead(cs *containerState, buf []byte, off int64) (int, error)
	onWrite(cs *containerState, buf []byte) (int, error)
}

// HandlerMap constructor.
func newHandlerMap() *handlerMap {

	var hm = map[string]handler{
		//
		// /proc handlers
		//
		"/proc/cpuinfo":      &cpuInfoHandler{},
		"/proc/cgroups":      &cgroupsHandler{},
		"/proc/devices":      &devicesHandler{},
		"/proc/diskstats":    &diskStatsHandler{},
		"/proc/loadavg":      &loadAvgHandler{},
		"/proc/meminfo":      &memInfoHandler{},
		"/proc/pagetypeinfo": &pagetypeInfoHandler{},
		"/proc/partitions":   &partitionsHandler{},
		"/proc/stat":         &statHandler{},
		"/proc/swaps":        &swapsHandler{},
		"/proc/sys":          &sysHandler{},
		"/proc/uptime":       &uptimeHandler{},
		//
		// /proc/sys/net handlers
		//
		"/proc/sys/net/netfilter/nf_conntrack_max":     &nfContrackMaxHandler{},
		"/proc/sys/net/bridge/bridge-nf-call-iptables": &nfCallIptableHandler{},
		"/proc/sys/net/ipv4/conf/all/route_localnet":   &routeLocalnetHandler{},
		//
		// /proc/sys/kernel handlers
		//
		"/proc/sys/kernel/panic":         &panicHandler{},
		"/proc/sys/kernel/panic_on_oops": &panicOopsHandler{},
		//
		// /proc/sys/vm handlers
		//
		"/proc/sys/vm/overcommit_memory": &overcommitMemoryHandler{},
	}

	return &hm
}

//
// Handler specializations
//

//
// cgroupsHandler
//
type cgroupsHandler struct{}

func (h *cgroupsHandler) onOpen(cs *containerState, flags fuse.OpenFlags) error {

	log.Println("Executing cgroupsHandler onOpen method")

	if flags != fuse.OpenReadOnly {
		return errors.New("/proc/cgroups: Permission denied")
	}

	return nil
}

func (h *cgroupsHandler) onRead(cs *containerState, buf []byte, off int64) (int, error) {

	log.Println("Executing cgroupsHandler onRead method")

	log.Println("Dumping something", cs.hostname)

	return 0, nil
}

func (h *cgroupsHandler) onWrite(cs *containerState, buf []byte) (int, error) {

	return 0, nil
}

//
// cpuInfoHandler
//
type cpuInfoHandler struct{}

func (h *cpuInfoHandler) onOpen(cs *containerState, flags fuse.OpenFlags) error {

	log.Println("Executing cpuInfoHandler onOpen method")

	if flags != fuse.OpenReadOnly {
		return errors.New("/proc/cpuinfo: Permission denied")
	}

	return nil
}

func (h *cpuInfoHandler) onRead(cs *containerState, buf []byte, off int64) (int, error) {

	log.Println("Executing cpuInfoHandler onRead method")

	log.Println("Dumping something", cs.hostname)

	return 0, nil
}

func (h *cpuInfoHandler) onWrite(cs *containerState, buf []byte) (int, error) {

	return 0, nil
}

//
// devicesHandler
//
type devicesHandler struct{}

func (h *devicesHandler) onOpen(cs *containerState, flags fuse.OpenFlags) error {

	log.Println("Executing devicesHandler onOpen method")

	if flags != fuse.OpenReadOnly {
		return errors.New("/proc/devices: Permission denied")
	}

	return nil
}

func (h *devicesHandler) onRead(cs *containerState, buf []byte, off int64) (int, error) {

	log.Println("Executing devicesHandler onRead method")

	log.Println("Dumping something", cs.hostname)

	return 0, nil
}

func (h *devicesHandler) onWrite(cs *containerState, buf []byte) (int, error) {

	return 0, nil
}

//
// diskStatsHandler
//
type diskStatsHandler struct{}

func (h *diskStatsHandler) onOpen(cs *containerState, flags fuse.OpenFlags) error {

	log.Println("Executing diskStatsHandler onOpen method")

	if flags != fuse.OpenReadOnly {
		return errors.New("/proc/diskstats: Permission denied")
	}

	return nil
}

func (h *diskStatsHandler) onRead(cs *containerState, buf []byte, off int64) (int, error) {

	log.Println("Executing diskStatsHandler onRead method")

	log.Println("Dumping something", cs.hostname)

	return 0, nil
}

func (h *diskStatsHandler) onWrite(cs *containerState, buf []byte) (int, error) {

	return 0, nil
}

//
// loadAvgHandler
//
type loadAvgHandler struct{}

func (h *loadAvgHandler) onOpen(cs *containerState, flags fuse.OpenFlags) error {

	log.Println("Executing loadAbgHandler onOpen method")

	if flags != fuse.OpenReadOnly {
		return errors.New("/proc/loadavg: Permission denied")
	}

	return nil
}

func (h *loadAvgHandler) onRead(cs *containerState, buf []byte, off int64) (int, error) {

	log.Println("Executing loadAvgHandler onRead method")

	log.Println("Dumping something", cs.hostname)

	return 0, nil
}

func (h *loadAvgHandler) onWrite(cs *containerState, buf []byte) (int, error) {

	return 0, nil
}

//
// memInfoHandler
//
type memInfoHandler struct{}

func (h *memInfoHandler) onOpen(cs *containerState, flags fuse.OpenFlags) error {

	log.Println("Executing memInfoHandler onOpen method")

	if flags != fuse.OpenReadOnly {
		return errors.New("/proc/meminfo: Permission denied")
	}

	return nil
}

func (h *memInfoHandler) onRead(cs *containerState, buf []byte, off int64) (int, error) {

	log.Println("Executing memInfoHandler onRead method")

	log.Println("Dumping something", cs.hostname)

	return 0, nil
}

func (h *memInfoHandler) onWrite(cs *containerState, buf []byte) (int, error) {

	return 0, nil
}

//
// pagetypeInfoHandler
//
type pagetypeInfoHandler struct{}

func (h *pagetypeInfoHandler) onOpen(cs *containerState, flags fuse.OpenFlags) error {

	log.Println("Executing pagetypeInfoHandler onOpen method")

	if flags != fuse.OpenReadOnly {
		return errors.New("/proc/pagetypeinfo: Permission denied")
	}

	return nil
}

func (h *pagetypeInfoHandler) onRead(cs *containerState, buf []byte, off int64) (int, error) {

	log.Println("Executing pagetypeInfoHandler onRead method")

	log.Println("Dumping something", cs.hostname)

	return 0, nil
}

func (h *pagetypeInfoHandler) onWrite(cs *containerState, buf []byte) (int, error) {

	return 0, nil
}

//
// partitionsHandler
//
type partitionsHandler struct{}

func (h *partitionsHandler) onOpen(cs *containerState, flags fuse.OpenFlags) error {

	log.Println("Executing partitionsHandler onOpen method")

	if flags != fuse.OpenReadOnly {
		return errors.New("/proc/partitions: Permission denied")
	}

	return nil
}

func (h *partitionsHandler) onRead(cs *containerState, buf []byte, off int64) (int, error) {

	log.Println("Executing partitionsHandler onRead method")

	log.Println("Dumping something", cs.hostname)

	return 0, nil
}

func (h *partitionsHandler) onWrite(cs *containerState, buf []byte) (int, error) {

	return 0, nil
}

//
// statHandler
//
type statHandler struct{}

func (h *statHandler) onOpen(cs *containerState, flags fuse.OpenFlags) error {

	log.Println("Executing statHandler onOpen method")

	if flags != fuse.OpenReadOnly {
		return errors.New("/proc/stat: Permission denied")
	}

	return nil
}

func (h *statHandler) onRead(cs *containerState, buf []byte, off int64) (int, error) {

	log.Println("Executing statHandler onRead method")

	log.Println("Dumping something", cs.hostname)

	return 0, nil
}

func (h *statHandler) onWrite(cs *containerState, buf []byte) (int, error) {

	return 0, nil
}

//
// swapsHandler
//
type swapsHandler struct{}

func (h *swapsHandler) onOpen(cs *containerState, flags fuse.OpenFlags) error {

	log.Println("Executing swapsHandler onOpen method")

	if flags != fuse.OpenReadOnly {
		return errors.New("/proc/swaps: Permission denied")
	}

	return nil
}

func (h *swapsHandler) onRead(cs *containerState, buf []byte, off int64) (int, error) {

	log.Println("Executing swapsHandler onRead method")

	log.Println("Dumping something", cs.hostname)

	return 0, nil
}

func (h *swapsHandler) onWrite(cs *containerState, buf []byte) (int, error) {

	return 0, nil
}

//
// sysHandler
//
type sysHandler struct{}

func (h *sysHandler) onOpen(cs *containerState, flags fuse.OpenFlags) error {

	log.Println("Executing sysHandler onOpen method")

	if flags != fuse.OpenReadOnly {
		return errors.New("/proc/sys: Permission denied")
	}

	return nil
}

func (h *sysHandler) onRead(cs *containerState, buf []byte, off int64) (int, error) {

	log.Println("Executing sysHandler onRead method")

	log.Println("Dumping something", cs.hostname)

	return 0, nil
}

func (h *sysHandler) onWrite(cs *containerState, buf []byte) (int, error) {

	return 0, nil
}

//
// uptimeHandler
//
type uptimeHandler struct{}

func (h *uptimeHandler) onOpen(cs *containerState, flags fuse.OpenFlags) error {

	log.Println("Executing uptimeHandler onOpen method")

	if flags != fuse.OpenReadOnly {
		return errors.New("/proc/uptime: Permission denied")
	}

	return nil
}

func (h *uptimeHandler) onRead(cs *containerState, buf []byte, off int64) (int, error) {

	log.Println("Executing uptimeHandler onRead method")

	if off > 0 {
		return 0, io.EOF
	}

	// Calculate container's uptime.
	uptime := time.Now().Unix() - cs.ctime.Unix()
	uptimeStr := strconv.FormatInt(uptime, 10)

	// TODO: Notice that we are dumping the same values into the two columns
	// expected in /proc/uptime. The value utilized for the first column is
	// an accurate one (uptime seconds), however, the second one is just
	// an approximation.
	copy(buf, uptimeStr+" "+uptimeStr)

	buf = buf[:len(buf)]

	return len(buf), nil
}

func (h *uptimeHandler) onWrite(cs *containerState, buf []byte) (int, error) {

	return 0, nil
}

//
// nfContrackMaxHandler
//
type nfContrackMaxHandler struct{}

func (h *nfContrackMaxHandler) onOpen(cs *containerState, flags fuse.OpenFlags) error {

	log.Println("Executing nfContrackMaxHandler onOpen method")

	if flags != fuse.OpenReadOnly && flags != fuse.OpenWriteOnly {
		return errors.New("/proc/sys/net/netfilter/nf_conntrack_max: Permission denied")
	}

	return nil
}

func (h *nfContrackMaxHandler) onRead(cs *containerState, buf []byte, off int64) (int, error) {

	log.Println("Executing nfContrakMaxHandler onRead method")

	if off > 0 {
		return 0, io.EOF
	}

	// Obtain stored value
	//val := cs.nfContrackMax
	val := 0
	valStr := strconv.Itoa(val)
	length := len(valStr)

	// Copy obtained value into result buffer
	copy(buf, valStr)
	buf = buf[:length]

	return length, nil
}

func (h *nfContrackMaxHandler) onWrite(cs *containerState, buf []byte) (int, error) {

	log.Println("Executing nfContrakMaxHandler onWrite method")

	// Buffer length expected to be returned to callee.
	buflen := len(buf)

	val, err := strconv.Atoi(strings.TrimSpace(string(buf)))
	if err != nil {
		return 0, err
	}

	// Store input value into container
	//cs.nfContrackMax = val

	log.Println("Storing nfcontrakMax value:", val)

	return buflen, nil
}

//
// nfCallIptableHandler
//
type nfCallIptableHandler struct{}

func (h *nfCallIptableHandler) onOpen(cs *containerState, flags fuse.OpenFlags) error {

	log.Println("Executing nfCallIptableHandler onOpen method")

	if flags != fuse.OpenReadOnly {
		return errors.New("/proc/sys/net/bridge/bridge-nf-call-iptables: Permission denied")
	}

	return nil
}

func (h *nfCallIptableHandler) onRead(cs *containerState, buf []byte, off int64) (int, error) {

	log.Println("Executing nfCallIptableHandler onRead method")

	log.Println("Dumping something", cs.hostname)

	return 0, nil
}

func (h *nfCallIptableHandler) onWrite(cs *containerState, buf []byte) (int, error) {

	return 0, nil
}

//
// routeLocalnetHandler
//
type routeLocalnetHandler struct{}

func (h *routeLocalnetHandler) onOpen(cs *containerState, flags fuse.OpenFlags) error {

	log.Println("Executing routeLocalnetHandler onOpen method")

	if flags != fuse.OpenReadOnly {
		return errors.New("/proc/sys/net/ipv4/conf/all/route_localnet: Permission denied")
	}

	return nil
}

func (h *routeLocalnetHandler) onRead(cs *containerState, buf []byte, off int64) (int, error) {

	log.Println("Executing routeLocalnetHandler onRead method")

	log.Println("Dumping something", cs.hostname)

	return 0, nil
}

func (h *routeLocalnetHandler) onWrite(cs *containerState, buf []byte) (int, error) {

	return 0, nil
}

//
// panicHandler
//
type panicHandler struct{}

func (h *panicHandler) onOpen(cs *containerState, flags fuse.OpenFlags) error {

	log.Println("Executing panicHandler onOpen method")

	if flags != fuse.OpenReadOnly {
		return errors.New("/proc/sys/kernel/panic: Permission denied")
	}

	return nil
}

func (h *panicHandler) onRead(cs *containerState, buf []byte, off int64) (int, error) {

	log.Println("Executing panicHandler onRead method")

	log.Println("Dumping something", cs.hostname)

	return 0, nil
}

func (h *panicHandler) onWrite(cs *containerState, buf []byte) (int, error) {

	return 0, nil
}

//
// panicOopsHandler
//
type panicOopsHandler struct{}

func (h *panicOopsHandler) onOpen(cs *containerState, flags fuse.OpenFlags) error {

	log.Println("Executing panicOopsHandler onOpen method")

	if flags != fuse.OpenReadOnly {
		return errors.New("/proc/sys/kernel/panic_on_oops: Permission denied")
	}

	return nil
}

func (h *panicOopsHandler) onRead(cs *containerState, buf []byte, off int64) (int, error) {

	log.Println("Executing panicOopsHandler onRead method")

	log.Println("Dumping something", cs.hostname)

	return 0, nil
}

func (h *panicOopsHandler) onWrite(cs *containerState, buf []byte) (int, error) {

	return 0, nil
}

//
// overcommitMemoryHandler
//
type overcommitMemoryHandler struct{}

func (h *overcommitMemoryHandler) onOpen(cs *containerState, flags fuse.OpenFlags) error {

	log.Println("Executing overcommitMemoryHandler onOpen method")

	if flags != fuse.OpenReadOnly {
		return errors.New("/proc/sys/vm/overcommit_memory: Permission denied")
	}

	return nil
}

func (h *overcommitMemoryHandler) onRead(cs *containerState, buf []byte, off int64) (int, error) {

	log.Println("Executing overcommitMemoryHandler onRead method")

	log.Println("Dumping something", cs.hostname)

	return 0, nil
}

func (h *overcommitMemoryHandler) onWrite(cs *containerState, buf []byte) (int, error) {

	return 0, nil
}
