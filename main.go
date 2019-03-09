package main

import (
	"flag"
	"fmt"
	"log"
	"os"

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
// Sysvisor-fs main function
//
func main() {

	flag.Usage = usage
	flag.Parse()

	if flag.NArg() != 1 {
		usage()
		os.Exit(-1)
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

	// Initialize sysvisorfs' gRPC server for runC's interaction
	go init_grpc_server()

	//
	// Creating a FUSE server to drive kernel interactions.
	//
	srv := fs.New(c, nil)

	//
	// Creating Sysvisor-fs making use of "/" as its root-path.
	//
	sysvisorfs = NewSysvisorFS("/")

	log.Println("About to serve sysvisorfs")
	if err := srv.Serve(sysvisorfs); err != nil {
		log.Panicln(err)
	}

	// Return if any error is reported by mount logic.
	<-c.Ready
	if err := c.MountError; err != nil {
		log.Fatal(err)
	}
}
