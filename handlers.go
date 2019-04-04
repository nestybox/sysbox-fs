package main

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"strconv"
	"strings"
	"text/template"
	"time"

	"bazil.org/fuse"
)

type handlerMap = map[string]handler

//
// Handler interface.
//
type handler interface {
	open(cs *containerState, flags *fuse.OpenFlags) error
	read(node ioNode, cs *containerState, buf []byte, off int64) (int, error)
	write(node ioNode, cs *containerState, buf []byte) (int, error)
	fetch(node ioNode, cs *containerState) (string, error)
	resource() string
}

// HandlerMap constructor.
func newHandlerMap() *handlerMap {

	var hm = map[string]handler{
		//
		// /proc handlers
		//
		"/proc/cpuinfo": &cpuInfoHandler{},
		// "/proc/cgroups":      &cgroupsHandler{},
		// "/proc/devices":      &devicesHandler{},
		// "/proc/diskstats":    &diskStatsHandler{},
		// "/proc/loadavg":      &loadAvgHandler{},
		// "/proc/meminfo":      &memInfoHandler{},
		// "/proc/pagetypeinfo": &pagetypeInfoHandler{},
		// "/proc/partitions":   &partitionsHandler{},
		// "/proc/stat":         &statHandler{},
		// "/proc/swaps":        &swapsHandler{},
		// "/proc/sys":          &sysHandler{},
		"/proc/uptime": &uptimeHandler{},
		//
		// /proc/sys/net handlers
		//
		"/proc/sys/net/netfilter/nf_conntrack_max": &nfConntrackMaxHandler{},
		"/proc/sys/net/ipv6/conf/all/disable_ipv6": &disableIpv6Handler{},
		// "/proc/sys/net/bridge/bridge-nf-call-iptables": &nfCallIptableHandler{},
		// "/proc/sys/net/ipv4/conf/all/route_localnet":   &routeLocalnetHandler{},
		//
		// /proc/sys/kernel handlers
		//
		// "/proc/sys/kernel/panic":         &panicHandler{},
		// "/proc/sys/kernel/panic_on_oops": &panicOopsHandler{},
		//
		// /proc/sys/vm handlers
		//
		//"/proc/sys/vm/overcommit_memory": &overcommitMemoryHandler{},
	}

	return &hm
}

//
// Handler specializations
//

//
// cpuInfoHandler
//
type cpuInfoHandler struct{}

func (h *cpuInfoHandler) open(cs *containerState, flags *fuse.OpenFlags) error {

	log.Println("Executing cpuInfoHandler open() method")

	// ReadOnly resource, enforce it.
	if flags == nil || *flags != fuse.OpenReadOnly {
		return errors.New("/proc/cpuinfo: Permission denied")
	}

	return nil
}

func (h *cpuInfoHandler) read(
	node ioNode,
	cs *containerState,
	buf []byte,
	off int64) (int, error) {

	log.Println("Executing cpuInfoHandler read method")

	if off > 0 {
		return 0, io.EOF
	}

	file := h.resource()

	//
	// Check if this resource has been initialized for this container. Otherwise
	// fetch the information from the host FS and store it accordingly within
	// the container struct.
	//
	_, ok := cs.stateDataMap[file]
	if !ok {
		if _, err := h.fetch(node, cs); err != nil {
			return 0, err
		}
	}

	// Extract auxiliar info from cpuset group controller.

	//
	// At this point, some container-state data must be available to serve this
	// request.
	//
	data, ok := cs.stateDataMap[file]
	if !ok {
		log.Println("Unexpected error")
		return 0, io.EOF
	}

	// TODO: Arrange this template-mess.
	t := template.Must(template.New("cpuInfo").Parse(cpuInfoTemplate))
	var tmp bytes.Buffer
	err := t.Execute(&tmp, data)
	if err != nil {
		log.Println("executing template:", err)
	}

	copy(buf, tmp.String())

	buf = buf[:len(buf)]

	return len(buf), nil
}

func (h *cpuInfoHandler) write(
	node ioNode,
	cs *containerState,
	buf []byte) (int, error) {

	return 0, nil
}

func (h *cpuInfoHandler) fetch(
	node ioNode,
	cs *containerState) (string, error) {

	file := h.resource()

	content, err := ioutil.ReadAll(node)
	if err != nil {
		log.Printf("Error reading %v file\n", file)
		return "", err
	}

	cpuInfoMap := make(map[string]string)

	lines := strings.Split(string(content), "\n")

	for _, line := range lines {
		elems := strings.Split(line, ":")

		// At least two, and no more than two columns are expected, otherwise
		// skip this record.
		if len(elems) != 2 {
			continue
		}
		leftColumn := strings.TrimSpace(elems[0])
		rightColumn := strings.TrimSpace(elems[1])

		cpuInfoMap[leftColumn] = rightColumn
	}

	cs.stateDataMap[file] = cpuInfoMap

	return "", nil
}

func (h *cpuInfoHandler) resource() string {

	return "/proc/cpuinfo"
}

/*
//
// cgroupsHandler
//
type cgroupsHandler struct {
	template string
}

func (h *cgroupsHandler) open(cs *containerState, flags fuse.OpenFlags) error {

	log.Println("Executing cgroupsHandler open() method")

	if flags != fuse.OpenReadOnly {
		return errors.New("/proc/cgroups: Permission denied")
	}

	return nil
}

func (h *cgroupsHandler) read(cs *containerState, buf []byte, off int64) (int, error) {

	log.Println("Executing cgroupsHandler read() method")

	log.Println("Dumping something", cs.hostname)

	return 0, nil
}

func (h *cgroupsHandler) write(cs *containerState, buf []byte) (int, error) {

	return 0, nil
}

//
// devicesHandler
//
type devicesHandler struct{}

func (h *devicesHandler) open(cs *containerState, flags fuse.OpenFlags) error {

	log.Println("Executing devicesHandler open() method")

	if flags != fuse.OpenReadOnly {
		return errors.New("/proc/devices: Permission denied")
	}

	return nil
}

func (h *devicesHandler) read(cs *containerState, buf []byte, off int64) (int, error) {

	log.Println("Executing devicesHandler read() method")

	log.Println("Dumping something", cs.hostname)

	return 0, nil
}

func (h *devicesHandler) write(cs *containerState, buf []byte) (int, error) {

	return 0, nil
}

//
// diskStatsHandler
//
type diskStatsHandler struct{}

func (h *diskStatsHandler) open(cs *containerState, flags fuse.OpenFlags) error {

	log.Println("Executing diskStatsHandler open() method")

	if flags != fuse.OpenReadOnly {
		return errors.New("/proc/diskstats: Permission denied")
	}

	return nil
}

func (h *diskStatsHandler) read(cs *containerState, buf []byte, off int64) (int, error) {

	log.Println("Executing diskStatsHandler read() method")

	log.Println("Dumping something", cs.hostname)

	return 0, nil
}

func (h *diskStatsHandler) write(cs *containerState, buf []byte) (int, error) {

	return 0, nil
}

//
// loadAvgHandler
//
type loadAvgHandler struct{}

func (h *loadAvgHandler) open(cs *containerState, flags fuse.OpenFlags) error {

	log.Println("Executing loadAbgHandler open() method")

	if flags != fuse.OpenReadOnly {
		return errors.New("/proc/loadavg: Permission denied")
	}

	return nil
}

func (h *loadAvgHandler) read(cs *containerState, buf []byte, off int64) (int, error) {

	log.Println("Executing loadAvgHandler read() method")

	log.Println("Dumping something", cs.hostname)

	return 0, nil
}

func (h *loadAvgHandler) write(cs *containerState, buf []byte) (int, error) {

	return 0, nil
}

//
// memInfoHandler
//
type memInfoHandler struct{}

func (h *memInfoHandler) open(cs *containerState, flags fuse.OpenFlags) error {

	log.Println("Executing memInfoHandler open() method")

	if flags != fuse.OpenReadOnly {
		return errors.New("/proc/meminfo: Permission denied")
	}

	return nil
}

func (h *memInfoHandler) read(cs *containerState, buf []byte, off int64) (int, error) {

	log.Println("Executing memInfoHandler read() method")

	log.Println("Dumping something", cs.hostname)

	return 0, nil
}

func (h *memInfoHandler) write(cs *containerState, buf []byte) (int, error) {

	return 0, nil
}

//
// pagetypeInfoHandler
//
type pagetypeInfoHandler struct{}

func (h *pagetypeInfoHandler) open(cs *containerState, flags fuse.OpenFlags) error {

	log.Println("Executing pagetypeInfoHandler open() method")

	if flags != fuse.OpenReadOnly {
		return errors.New("/proc/pagetypeinfo: Permission denied")
	}

	return nil
}

func (h *pagetypeInfoHandler) read(cs *containerState, buf []byte, off int64) (int, error) {

	log.Println("Executing pagetypeInfoHandler read() method")

	log.Println("Dumping something", cs.hostname)

	return 0, nil
}

func (h *pagetypeInfoHandler) write(cs *containerState, buf []byte) (int, error) {

	return 0, nil
}

//
// partitionsHandler
//
type partitionsHandler struct{}

func (h *partitionsHandler) open(cs *containerState, flags fuse.OpenFlags) error {

	log.Println("Executing partitionsHandler open() method")

	if flags != fuse.OpenReadOnly {
		return errors.New("/proc/partitions: Permission denied")
	}

	return nil
}

func (h *partitionsHandler) read(cs *containerState, buf []byte, off int64) (int, error) {

	log.Println("Executing partitionsHandler read() method")

	log.Println("Dumping something", cs.hostname)

	return 0, nil
}

func (h *partitionsHandler) write(cs *containerState, buf []byte) (int, error) {

	return 0, nil
}

//
// statHandler
//
type statHandler struct{}

func (h *statHandler) open(cs *containerState, flags fuse.OpenFlags) error {

	log.Println("Executing statHandler open() method")

	if flags != fuse.OpenReadOnly {
		return errors.New("/proc/stat: Permission denied")
	}

	return nil
}

func (h *statHandler) read(cs *containerState, buf []byte, off int64) (int, error) {

	log.Println("Executing statHandler read() method")

	log.Println("Dumping something", cs.hostname)

	return 0, nil
}

func (h *statHandler) write(cs *containerState, buf []byte) (int, error) {

	return 0, nil
}

//
// swapsHandler
//
type swapsHandler struct{}

func (h *swapsHandler) open(cs *containerState, flags fuse.OpenFlags) error {

	log.Println("Executing swapsHandler open() method")

	if flags != fuse.OpenReadOnly {
		return errors.New("/proc/swaps: Permission denied")
	}

	return nil
}

func (h *swapsHandler) read(cs *containerState, buf []byte, off int64) (int, error) {

	log.Println("Executing swapsHandler read() method")

	log.Println("Dumping something", cs.hostname)

	return 0, nil
}

func (h *swapsHandler) write(cs *containerState, buf []byte) (int, error) {

	return 0, nil
}

//
// sysHandler
//
type sysHandler struct{}

func (h *sysHandler) open(cs *containerState, flags fuse.OpenFlags) error {

	log.Println("Executing sysHandler open() method")

	if flags != fuse.OpenReadOnly {
		return errors.New("/proc/sys: Permission denied")
	}

	return nil
}

func (h *sysHandler) read(cs *containerState, buf []byte, off int64) (int, error) {

	log.Println("Executing sysHandler read() method")

	log.Println("Dumping something", cs.hostname)

	return 0, nil
}

func (h *sysHandler) write(cs *containerState, buf []byte) (int, error) {

	return 0, nil
}
*/

//
// uptimeHandler -- to serve /proc/uptime
//
type uptimeHandler struct{}

func (h *uptimeHandler) open(cs *containerState, flags *fuse.OpenFlags) error {

	log.Println("Executing uptimeHandler's open() method")

	// ReadOnly resource, enforce it.
	if flags == nil || *flags != fuse.OpenReadOnly {
		return errors.New("/proc/uptime: Permission denied")
	}

	return nil
}

func (h *uptimeHandler) read(
	node ioNode,
	cs *containerState,
	buf []byte,
	off int64) (int, error) {

	log.Println("Executing uptimeHandler's read() method")

	if off > 0 {
		return 0, io.EOF
	}

	//
	// We can assume that by the time a user generates a request to read
	// /proc/uptime, the embedding container has been fully initialized,
	// so cs.ctime is already holding a valid value.
	//
	data := cs.ctime

	// Calculate container's uptime.
	uptime := time.Now().Unix() - data.Unix()
	uptimeStr := strconv.FormatInt(uptime, 10)

	//
	// TODO: Notice that we are dumping the same values into the two columns
	// expected in /proc/uptime. The value utilized for the first column is
	// an accurate one (uptime seconds), however, the second one is just
	// an approximation.
	//
	res := uptimeStr + " " + uptimeStr
	copy(buf, res)
	buf = buf[:len(res)]

	return len(buf), nil
}

// Read-only resource, no need for write() method.
func (h *uptimeHandler) write(
	node ioNode,
	cs *containerState,
	buf []byte) (int, error) {

	return 0, nil
}

//
// Uptime value is obtained directly from sysvisor-runc, so there's no need
// for a fetch() method.
//
func (h *uptimeHandler) fetch(
	node ioNode,
	cs *containerState) (string, error) {

	return "", nil
}

func (h *uptimeHandler) resource() string {

	return "/proc/uptime"
}

//
// nfConntrackMaxHandler
//
type nfConntrackMaxHandler struct{}

func (h *nfConntrackMaxHandler) open(cs *containerState, flags *fuse.OpenFlags) error {

	log.Println("Executing nfConntrackMaxHandler open() method")

	if flags == nil || (*flags != fuse.OpenReadOnly && *flags != fuse.OpenWriteOnly) {
		return errors.New("/proc/sys/net/netfilter/nf_conntrack_max: Permission denied")
	}

	// During 'writeOnly' accesses, we must grant read-write rights temporarily
	// to allow push() to carry out the expected 'write' operation, as well as a
	// 'read' one too.
	if *flags == fuse.OpenWriteOnly {
		*flags = fuse.OpenReadWrite
	}

	return nil
}

func (h *nfConntrackMaxHandler) read(
	node ioNode,
	cs *containerState,
	buf []byte,
	off int64) (int, error) {

	log.Println("Executing nfConntrakMaxHandler read() method")

	if off > 0 {
		return 0, io.EOF
	}

	file := h.resource()

	//
	// Check if this resource has been initialized for this container. Otherwise,
	// fetch the information from the host FS and store it accordingly within
	// the container struct.
	//
	_, ok := cs.stateDataMap[file]
	if !ok {
		content, err := h.fetch(node, cs)
		if err != nil {
			return 0, err
		}

		nfConntrackMaxMap := map[string]string{
			"nf_conntrack_max": content,
		}

		cs.stateDataMap[file] = nfConntrackMaxMap
	}

	//
	// At this point, some container-state data must be available to serve this
	// request.
	//
	data, ok := cs.stateDataMap[file]["nf_conntrack_max"]
	if !ok {
		log.Println("Unexpected error")
		return 0, io.EOF
	}

	copy(buf, data)
	length := len(data)
	buf = buf[:length]

	return length, nil
}

func (h *nfConntrackMaxHandler) write(
	node ioNode,
	cs *containerState,
	buf []byte) (int, error) {

	log.Println("Executing nfConntrakMaxHandler write() method")

	file := h.resource()

	newMax := strings.TrimSpace(string(buf))
	newMaxInt, err := strconv.Atoi(newMax)
	if err != nil {
		log.Println("Unexpected error:", err)
		return 0, err
	}

	//
	// Check if this resource has been initialized for this container. If not,
	// push it to the host FS and store it within the container struct.
	//
	_, ok := cs.stateDataMap[file]
	if !ok {
		if err := h.push(node, cs, newMaxInt); err != nil {
			return 0, err
		}

		nfConntrackMaxMap := map[string]string{
			"nf_conntrack_max": newMax,
		}
		cs.stateDataMap[file] = nfConntrackMaxMap

		return len(buf), nil
	}

	// Obtain existing value stored/cached in this container struct.
	curMax, ok := cs.stateDataMap[file]["nf_conntrack_max"]
	if !ok {
		log.Println("Unexpected error")
		return 0, err
	}

	curMaxInt, err := strconv.Atoi(curMax)
	if err != nil {
		log.Println("Unexpected error:", err)
		return 0, err
	}

	//
	// If new value is lower/equal than the existing one, then let's update this
	// new value into the container struct and return here. Notice that we cannot
	// push this (lower-than-current) value into the host FS, as we could be
	// impacting other syscontainers.
	//
	if newMaxInt <= curMaxInt {
		cs.stateDataMap[file]["nf_conntrack_max"] = newMax

		return len(buf), nil
	}

	// Push new value to host FS.
	if err := h.push(node, cs, newMaxInt); err != nil {
		return 0, io.EOF
	}

	// Writing the new value into container-state struct.
	cs.stateDataMap[file]["nf_conntrack_max"] = newMax

	return len(buf), nil
}

func (h *nfConntrackMaxHandler) fetch(
	node ioNode,
	cs *containerState) (string, error) {

	file := h.resource()

	// Read from host FS to extract the existing nf_conntrack_max value.
	content, err := ioutil.ReadAll(node)
	if err != nil {
		log.Printf("Could not read from file %s", file)
		return "", err
	}

	// Parse received data.
	lines := strings.Split(string(content), "\n")

	if len(lines) > 2 {
		log.Printf("Unexpected number of lines for this file: %d\n", len(lines))
		return "", errors.New("Unexpected file format")
	}

	return lines[0], nil

}

func (h *nfConntrackMaxHandler) push(
	node ioNode,
	cs *containerState,
	newMaxInt int) error {

	file := h.resource()

	// Read from host FS to extract the existing nf_conntrack_max value.
	content, err := ioutil.ReadAll(node)
	if err != nil {
		log.Printf("Could not read from file %s", file)
		return err
	}

	lines := strings.Split(string(content), "\n")
	if len(lines) > 2 {
		log.Printf("Unexpected number of lines for this file: %d\n", len(lines))
		return errors.New("Unexpected file format")
	}

	curHostMax := lines[0]
	curHostMaxInt, err := strconv.Atoi(curHostMax)
	if err != nil {
		log.Println("Unexpected error:", err)
		return err
	}

	//
	// If the existing host FS value is larger than the new one to configure,
	// then let's just return here as we want to keep the largest value
	// in the host FS.
	//
	if newMaxInt <= curHostMaxInt {
		return nil
	}

	// Push down to host FS the new (larger) value.
	msg := []byte(strconv.Itoa(newMaxInt))
	io.Copy(node, bytes.NewReader(msg))
	if err != nil {
		log.Printf("Unexpected error: %s\n", err)
	}

	return nil
}

func (h *nfConntrackMaxHandler) resource() string {

	return "/proc/sys/net/netfilter/nf_conntrack_max"
}

//
// disableIpv6Handler
//
type disableIpv6Handler struct{}

func (h *disableIpv6Handler) open(cs *containerState, flags *fuse.OpenFlags) error {

	log.Println("Executing disableIpv6Handler open() method")

	if flags == nil || (*flags != fuse.OpenReadOnly && *flags != fuse.OpenWriteOnly) {
		return errors.New("/proc/sys/net/ipv6/conf/all/disable_ipv6: Permission denied")
	}

	return nil
}

func (h *disableIpv6Handler) read(
	node ioNode,
	cs *containerState,
	buf []byte,
	off int64) (int, error) {

	log.Println("Executing disableIpv6Handler read() method")

	if off > 0 {
		return 0, io.EOF
	}

	file := h.resource()

	//
	// Check if this resource has been initialized for this container. Otherwise
	// fetch the information from the host FS and store it accordingly within
	// the container struct.
	//
	_, ok := cs.stateDataMap[file]
	if !ok {
		content, err := h.fetch(node, cs)
		if err != nil {
			return 0, err
		}

		disableIpv6Map := map[string]string{
			"disable_ipv6": content,
		}

		cs.stateDataMap[file] = disableIpv6Map
	}

	//
	// At this point, some container-state data must be available to serve this
	// request.
	//
	data, ok := cs.stateDataMap[file]["disable_ipv6"]
	if !ok {
		log.Println("Unexpected error")
		return 0, io.EOF
	}

	copy(buf, data)
	length := len(data)
	buf = buf[:length]

	return length, nil
}

func (h *disableIpv6Handler) write(
	node ioNode,
	cs *containerState,
	buf []byte) (int, error) {

	log.Println("Executing disableIpv6Handler write() method")

	file := h.resource()

	newVal := strings.TrimSpace(string(buf))
	newValInt, err := strconv.Atoi(newVal)
	if err != nil {
		log.Println("Unexpected error:", err)
		return 0, err
	}

	//
	// Check if this resource has been initialized for this container. If not,
	// push it to the host FS and store it within the container struct.
	//
	_, ok := cs.stateDataMap[file]
	if !ok {
		if err := h.push(node, cs, newVal); err != nil {
			return 0, io.EOF
		}

		disableIpv6Map := map[string]string{
			"disable_ipv6": newVal,
		}
		cs.stateDataMap[file] = disableIpv6Map

		return len(buf), nil
	}

	// Obtain existing value stored in this container.
	curVal, ok := cs.stateDataMap[file]["disable_ipv6"]
	if !ok {
		log.Println("Unexpected error", err)
		return 0, errors.New("Unexpected error")
	}
	curValInt, err := strconv.Atoi(curVal)
	if err != nil {
		log.Println("Unexpected error:", err)
		return 0, err
	}

	//
	// If new value matches the existing one, then there's noting else to be
	// done here.
	//
	if newValInt == curValInt {
		return len(buf), nil
	}

	// Push new value to host FS.
	if err := h.push(node, cs, newVal); err != nil {
		return 0, err
	}

	// Writing the new value into container-state struct.
	cs.stateDataMap[file]["disable_ipv6"] = newVal

	return len(buf), nil
}

func (h *disableIpv6Handler) fetch(
	node ioNode,
	cs *containerState) (string, error) {

	event := &nsenterEvent{
		Resource:  h.resource(),
		Message:   readRequest,
		Content:   "",
		Pid:       cs.initPid,
		Namespace: []nsType{string(nsTypeNet)},
	}

	res, err := event.launch()
	if err != nil {
		return "", err
	}

	return res.Content, nil
}

func (h *disableIpv6Handler) push(
	node ioNode,
	cs *containerState,
	newVal string) error {

	event := &nsenterEvent{
		Resource:  h.resource(),
		Message:   writeRequest,
		Content:   newVal,
		Pid:       cs.initPid,
		Namespace: []nsType{string(nsTypeNet)},
	}

	if _, err := event.launch(); err != nil {
		return err
	}

	return nil
}

func (h *disableIpv6Handler) resource() string {

	return "/proc/sys/net/ipv6/conf/all/disable_ipv6"
}

/*
//
// nfCallIptableHandler
//
type nfCallIptableHandler struct{}

func (h *nfCallIptableHandler) open(cs *containerState, flags fuse.OpenFlags) error {

	log.Println("Executing nfCallIptableHandler open() method")

	if flags != fuse.OpenReadOnly {
		return errors.New("/proc/sys/net/bridge/bridge-nf-call-iptables: Permission denied")
	}

	return nil
}

func (h *nfCallIptableHandler) read(cs *containerState, buf []byte, off int64) (int, error) {

	log.Println("Executing nfCallIptableHandler read() method")

	log.Println("Dumping something", cs.hostname)

	return 0, nil
}

func (h *nfCallIptableHandler) write(cs *containerState, buf []byte) (int, error) {

	return 0, nil
}

//
// routeLocalnetHandler
//
type routeLocalnetHandler struct{}

func (h *routeLocalnetHandler) open(cs *containerState, flags fuse.OpenFlags) error {

	log.Println("Executing routeLocalnetHandler open() method")

	if flags != fuse.OpenReadOnly {
		return errors.New("/proc/sys/net/ipv4/conf/all/route_localnet: Permission denied")
	}

	return nil
}

func (h *routeLocalnetHandler) read(cs *containerState, buf []byte, off int64) (int, error) {

	log.Println("Executing routeLocalnetHandler read() method")

	log.Println("Dumping something", cs.hostname)

	return 0, nil
}

func (h *routeLocalnetHandler) write(cs *containerState, buf []byte) (int, error) {

	return 0, nil
}

//
// panicHandler
//
type panicHandler struct{}

func (h *panicHandler) open(cs *containerState, flags fuse.OpenFlags) error {

	log.Println("Executing panicHandler open() method")

	if flags != fuse.OpenReadOnly {
		return errors.New("/proc/sys/kernel/panic: Permission denied")
	}

	return nil
}

func (h *panicHandler) read(cs *containerState, buf []byte, off int64) (int, error) {

	log.Println("Executing panicHandler read() method")

	log.Println("Dumping something", cs.hostname)

	return 0, nil
}

func (h *panicHandler) write(cs *containerState, buf []byte) (int, error) {

	return 0, nil
}

//
// panicOopsHandler
//
type panicOopsHandler struct{}

func (h *panicOopsHandler) open(cs *containerState, flags fuse.OpenFlags) error {

	log.Println("Executing panicOopsHandler open() method")

	if flags != fuse.OpenReadOnly {
		return errors.New("/proc/sys/kernel/panic_on_oops: Permission denied")
	}

	return nil
}

func (h *panicOopsHandler) read(cs *containerState, buf []byte, off int64) (int, error) {

	log.Println("Executing panicOopsHandler read() method")

	log.Println("Dumping something", cs.hostname)

	return 0, nil
}

func (h *panicOopsHandler) write(cs *containerState, buf []byte) (int, error) {

	return 0, nil
}

//
// overcommitMemoryHandler
//
type overcommitMemoryHandler struct{}

func (h *overcommitMemoryHandler) open(cs *containerState, flags fuse.OpenFlags) error {

	log.Println("Executing overcommitMemoryHandler open() method")

	if flags != fuse.OpenReadOnly {
		return errors.New("/proc/sys/vm/overcommit_memory: Permission denied")
	}

	return nil
}

func (h *overcommitMemoryHandler) read(cs *containerState, buf []byte, off int64) (int, error) {

	log.Println("Executing overcommitMemoryHandler read() method")

	log.Println("Dumping something", cs.hostname)

	return 0, nil
}

func (h *overcommitMemoryHandler) write(cs *containerState, buf []byte) (int, error) {

	return 0, nil
}
*/
