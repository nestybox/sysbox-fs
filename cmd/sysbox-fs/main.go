//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
	"github.com/nestybox/sysbox-fs/handler"
	"github.com/nestybox/sysbox-fs/ipc"
	"github.com/nestybox/sysbox-fs/nsenter"
	"github.com/nestybox/sysbox-fs/process"
	"github.com/nestybox/sysbox-fs/seccomp"
	"github.com/nestybox/sysbox-fs/state"
	"github.com/nestybox/sysbox-fs/sysio"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"

	"golang.org/x/sys/unix"
)

// TODO: Improve one-liner description.
const (
	usage = `sysbox-fs file-system

sysbox-fs is a daemon that provides enhanced file-system capabilities to
sysbox-runc component.
`
)

// Globals to be populated at build time during Makefile processing.
var (
	version  string // extracted from VERSION file
	commitId string // latest git commit-id of sysbox superproject
	builtAt  string // build time
	builtBy  string // build owner
)

//
// sysbox-fs exit handler goroutine.
//
func exitHandler(signalChan chan os.Signal, fs domain.FuseService) {

	s := <-signalChan
	logrus.Warnf("Caught OS signal: %s", s)

	// Unmount sysbox-fs
	logrus.Infof("Unmounting sysbox-fs from mountpoint %v.", fs.MountPoint())
	fs.Unmount()

	// Deferring exit() to allow FUSE to dump unnmount() logs
	time.Sleep(2)

	logrus.Info("Exiting.")
	os.Exit(0)
}

//
// sysbox-fs child reaper: reaps zombie child processes that sometimes occur when
// sysbox-fs dispatches nsenter processes to perform actions within the sys container's
// namespace.
//
// This child reaper is really a "backup" reaper, as normally the function that dispatches
// the nsenter process performs the reaping, though in some cases that reaping does not
// occur due to inherent race conditions that occur when the nsenter occurs at a time
// when a sys container is being destroyed. For those cases, this reaper cleans left-over
// zombies.
//
// Note: a user can also request sysbox-fs to execute this reaper via:
//
// $ sudo kill -s SIGCHLD $(pidof sysbox-fs)
//

func childReaper(signalChan chan os.Signal) {
	var wstatus syscall.WaitStatus

	for {
		<-signalChan

		// We are a backup reaper, so we wait after receiving SIGCHLD for any left-over zombies
		time.Sleep(5 * time.Second)

		wpid, err := syscall.Wait4(-1, &wstatus, 0, nil)
		if err != nil {
			continue
		}

		logrus.Debugf("Reaped left-over child pid %d", wpid)
	}
}

//
// sysbox-fs main function
//
func main() {

	app := cli.NewApp()
	app.Name = "sysbox-fs"
	app.Usage = usage
	app.Version = version

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "mountpoint",
			Value: "/var/lib/sysboxfs",
			Usage: "mount-point location",
		},
		cli.StringFlag{
			Name:  "log",
			Value: "/dev/stdout",
			Usage: "log file path",
		},
		cli.StringFlag{
			Name:  "log-level",
			Value: "info",
			Usage: "log categories to include (debug, info, warning, error, fatal)",
		},
		cli.IntFlag{
			Name:        "dentry-cache-timeout, t",
			Value:       fuse.DentryCacheTimeout,
			Usage:       "dentry-cache-timeout timer in minutes",
			Destination: &fuse.DentryCacheTimeout,
		},
		cli.BoolFlag{
			Name:  "ignore-handler-errors",
			Usage: "ignore errors during procfs / sysfs node interactions (testing purposes)",
		},
	}

	// show-version specialization.
	cli.VersionPrinter = func(c *cli.Context) {
		fmt.Printf("sysbox-fs\n"+
			"\tversion: \t%s\n"+
			"\tcommit: \t%s\n"+
			"\tbuilt at: \t%s\n"+
			"\tbuilt by: \t%s\n",
			c.App.Version, commitId, builtAt, builtBy)
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

		// Create/set the log-file destination.
		if path := ctx.GlobalString("log"); path != "" {
			f, err := os.OpenFile(
				path,
				os.O_CREATE|os.O_WRONLY|os.O_APPEND|os.O_SYNC,
				0666,
			)
			if err != nil {
				logrus.Fatalf(
					"Error opening log file %v: %v. Exiting ...",
					path, err,
				)
				return err
			}

			// Set a proper logging formatter.
			logrus.SetFormatter(&logrus.TextFormatter{
				ForceColors:     true,
				TimestampFormat: "2006-01-02 15:04:05",
				FullTimestamp:   true,
			})
			logrus.SetOutput(f)
			log.SetOutput(f)
		}

		// Set desired log-level.
		if logLevel := ctx.GlobalString("log-level"); logLevel != "" {
			switch logLevel {
			case "debug":
				// Following instruction is to have Bazil's fuze-lib logs being
				// included into sysbox-fs' log stream.
				flag.Set("fuse.debug", "true")
				logrus.SetLevel(logrus.DebugLevel)
			case "info":
				logrus.SetLevel(logrus.InfoLevel)
			case "warning":
				logrus.SetLevel(logrus.WarnLevel)
			case "error":
				logrus.SetLevel(logrus.ErrorLevel)
			case "fatal":
				logrus.SetLevel(logrus.FatalLevel)
			default:
				logrus.Fatalf(
					"log-level option '%v' not recognized. Exiting ...",
					logLevel,
				)
			}
		} else {
			// Set 'info' as our default log-level.
			logrus.SetLevel(logrus.InfoLevel)
		}

		return nil
	}

	// sysbox-fs main-loop execution.
	app.Action = func(ctx *cli.Context) error {

		// Initialize sysbox-fs' services.

		var processService = process.NewProcessService()

		var nsenterService = nsenter.NewNSenterService(processService)

		var ioService = sysio.NewIOService(sysio.IOFileService)

		var containerStateService = state.NewContainerStateService(
			processService,
			ioService,
		)

		var handlerService = handler.NewHandlerService(
			handler.DefaultHandlers,
			containerStateService,
			nsenterService,
			processService,
			ioService,
			ctx.Bool("ignore-handler-errors"),
		)

		var syscallMonitorService = seccomp.NewSyscallMonitorService(
			nsenterService,
			containerStateService,
			handlerService,
			processService,
		)
		if syscallMonitorService == nil {
			logrus.Fatal("syscallMonitorService initialization error. Exiting ...")
		}

		var ipcService = ipc.NewIpcService(
			containerStateService,
			processService,
			ioService)
		if ipcService == nil {
			logrus.Fatal("IpcService initialization error. Exiting ...")
		}
		ipcService.Init()

		var fuseService = fuse.NewFuseService(
			"/",
			ctx.GlobalString("mountpoint"),
			ioService,
			handlerService,
		)
		if fuseService == nil {
			logrus.Fatal("FuseService initialization error. Exiting ...")
		}

		// TODO: Consider adding sync.Workgroups to ensure that all goroutines
		// are done with their in-flight tasks before exit()ing.

		// Launch exit handler (performs proper cleanup of sysbox-fs upon receiving
		// termination signals)
		var exitChan = make(chan os.Signal, 1)
		signal.Notify(
			exitChan,
			syscall.SIGHUP,
			syscall.SIGINT,
			syscall.SIGTERM,
			syscall.SIGSEGV,
			syscall.SIGQUIT)
		go exitHandler(exitChan, fuseService)

		// Launch the sysbox-fs child reaper (cleans up zombie childs)
		err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)
		if err != nil {
			logrus.Fatalf("Failed to set sysbox-fs as child subreaper: %s", err)
		}

		var childReaperChan = make(chan os.Signal, 1)
		signal.Notify(
			childReaperChan,
			syscall.SIGCHLD)
		go childReaper(childReaperChan)

		// Initiate sysbox-fs' FUSE service.
		if err := fuseService.Run(); err != nil {
			logrus.Panic(err)
		}

		return nil
	}

	if err := app.Run(os.Args); err != nil {
		logrus.Panic(err)
	}
}
