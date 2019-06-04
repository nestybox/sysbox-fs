package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nestybox/sysvisor-fs/domain"
	"github.com/nestybox/sysvisor-fs/fuse"
	"github.com/nestybox/sysvisor-fs/handler"
	"github.com/nestybox/sysvisor-fs/ipc"
	"github.com/nestybox/sysvisor-fs/nsenter"
	"github.com/nestybox/sysvisor-fs/state"
	"github.com/nestybox/sysvisor-fs/sysio"

	"github.com/urfave/cli"
)

// TODO: Improve one-liner description.
const (
	usage = `sysvisor file-system

sysvisor-fs is a daemon that provides enhanced file-system capabilities to
sysvisor-runc component.
`
)

//
// Sysvisorfs signal handler goroutine.
//
func signalHandler(signalChan chan os.Signal, fs domain.FuseService) {

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

	log.Println("Unmounting sysvisorfs from mountpoint", fs.MountPoint(), "Exitting...")
	fs.Unmount()

	// Deferring exit() to allow FUSE to dump unnmount() logs
	time.Sleep(2)

	os.Exit(0)
}

//
// Sysvisor-fs main function
//
func main() {

	app := cli.NewApp()
	app.Name = "sysvisor-fs"
	app.Usage = usage

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "mountpoint",
			Value: "/var/lib/sysvisorfs",
			Usage: "mount-point location",
		},
		cli.BoolFlag{
			Name:  "debug, d",
			Usage: "enable debug output in logs",
		},
		cli.StringFlag{
			Name:  "log",
			Value: "/dev/null",
			Usage: "log file path",
		},
	}

	// Nsenter command to allow 'rexec' functionality.
	app.Commands = []cli.Command{
		{
			Name:  "nsenter",
			Usage: "Execute action within container namespaces",
			Action: func(c *cli.Context) error {
				nsenter.Init()
				return nil
			},
		},
	}

	// Define 'debug' and 'log' settings.
	app.Before = func(ctx *cli.Context) error {

		// For troubleshooting purposes, if 'debug' option is enabled, we want
		// to dump all sysvisor-fs logs, as well as Bazil fuse-lib ones, into
		// the same log file. With that goal in mind is that we are artificially
		// setting this flag, which is eventually consumed by Bazil code.
		if ctx.GlobalBool("debug") {
			flag.Set("fuse.debug", "true")
		}

		// Create/set the log-file destination.
		if path := ctx.GlobalString("log"); path != "" {
			f, err := os.OpenFile(
				path,
				os.O_CREATE|os.O_WRONLY|os.O_APPEND|os.O_SYNC,
				0666,
			)
			if err != nil {
				log.Fatalf("Error opening log file %v: %v", path, err)
				return err
			}

			log.SetOutput(f)
		}
		return nil
	}

	// Sysvisor-fs main-loop execution.
	app.Action = func(ctx *cli.Context) error {

		// Initialize sysvisor-fs' services.
		var containerStateService = state.NewContainerStateService()
		var nsenterService = nsenter.NewNSenterService()
		var ioService = sysio.NewIOService(sysio.IOFileService)

		var handlerService = handler.NewHandlerService(
			handler.DefaultHandlers,
			containerStateService,
			nsenterService,
			ioService)

		var ipcService = ipc.NewIpcService(containerStateService, ioService)
		ipcService.Init()

		var fuseService = fuse.NewFuseService(
			"/",
			ctx.GlobalString("mountpoint"),
			ioService,
			handlerService)

		// Launch signal-handler to ensure mountpoint is properly unmounted
		// during shutdown.
		var signalChan = make(chan os.Signal)
		signal.Notify(
			signalChan,
			syscall.SIGHUP,
			syscall.SIGINT,
			syscall.SIGTERM,
			syscall.SIGSEGV,
			syscall.SIGQUIT)
		go signalHandler(signalChan, fuseService)

		// Initiate sysvisor-fs' FUSE service.
		if err := fuseService.Run(); err != nil {
			log.Fatal(err)
		}

		return nil
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
