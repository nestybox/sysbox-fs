package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
	_ "bazil.org/fuse/fs/fstestutil"
)

func usage() {
	fmt.Fprintf(os.Stderr, "Usafe of %s\n", os.Args[0])
	fmt.Fprintf(os.Stderr, " %s <file-system mount-point>\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "\n Example: sysvisorfs /var/lib/sysvisorfs\n\n")
	fmt.Fprintf(os.Stderr, "OtherFUSE options:\n")
	flag.PrintDefaults()
}

//
// Sysvisorfs signal handler goroutine.
//
func signalHandler(signalChan chan os.Signal, mountPoint string) {

	s := <-signalChan
	switch s {

	// TODO: Handle SIGHUP differently -- e.g. re-read sysvisorfs conf file
	case syscall.SIGHUP:
		log.Println("Sysvisorfs caught signal: SIGHUP")

	case syscall.SIGSEGV:
		log.Println("Sysvisorfs caught signal: SIGSEGV")

	case syscall.SIGINT:
		log.Println("Sysvisorfs caught signal: SIGTINT")

	case syscall.SIGTERM:
		log.Println("Sysvisorfs caught signal: SIGTERM")

	case syscall.SIGQUIT:
		log.Println("Sysvisorfs caught signal: SIGQUIT")

	default:
		log.Println("Sysvisorfs caught unknown signal")
	}

	log.Println("Unmounting sysvisorfs from mountpoint", mountPoint, "Exitting...")
	fuse.Unmount(mountPoint)

	// Deferring exit() to allow FUSE to dump unnmount() logs
	time.Sleep(2)

	os.Exit(0)
}

//
// Sysvisor-fs main function
//
func main() {

	flag.Usage = usage
	flag.Parse()

	if flag.NArg() != 1 {
		usage()
		os.Exit(-1)
	}

	// TODO: Enhance cli/parsing logic (this is lame).
	if flag.Arg(0) == "nsenter" {
		nsenter()
		return
	}

	// Sysvisor-fs mountpoint
	mountPoint := flag.Arg(0)

	//
	// Creating a FUSE mount at the requested mountpoint. Notice that we are making use
	// of "allowOther" flag to allow unpriviliged users to access this mount.
	//
	c, err := fuse.Mount(
		mountPoint,
		fuse.FSName("sysvisorfs"),
		fuse.AllowOther())
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()
	if p := c.Protocol(); !p.HasInvalidate() {
		log.Panicln("Kernel FUSE support is too old to have invalidations: version %v", p)
	}

	// Ensure sysvisor-fs is properly unmounted during shutdown.
	var signalChan = make(chan os.Signal)
	signal.Notify(
		signalChan,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGSEGV,
		syscall.SIGQUIT)
	go signalHandler(signalChan, mountPoint)

	//
	// Creating a FUSE server to drive kernel interactions.
	//
	srv := fs.New(c, nil)

	//
	// Creating Sysvisor-fs making use of "/" as its root-path.
	//
	sysfs = newSysvisorFS("/")

	// Initialize sysvisorfs' gRPC server for runC's interaction
	go initGrpcServer(sysfs)

	log.Println("About to serve sysvisorfs")
	if err := srv.Serve(sysfs); err != nil {
		log.Panicln(err)
	}

	// Return if any error is reported by mount logic.
	<-c.Ready
	if err := c.MountError; err != nil {
		log.Fatal(err)
	}
}
