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
	"github.com/nestybox/sysbox-fs/state"
	"github.com/nestybox/sysbox-fs/sysio"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
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
	version   string // extracted from VERSION file
	commitId  string // latest git commit-id of sysbox superproject
	builtAt   string // build time
	builtBy   string // build owner
)

//
// sysbox-fs signal handler goroutine.
//
func signalHandler(signalChan chan os.Signal, fs domain.FuseService) {

	s := <-signalChan

	switch s {

	// TODO: Handle SIGHUP differently -- e.g. re-read sysbox-fs conf file
	case syscall.SIGHUP:
		logrus.Warn("sysbox-fs caught signal: SIGHUP")

	case syscall.SIGSEGV:
		logrus.Warn("sysbox-fs caught signal: SIGSEGV")

	case syscall.SIGINT:
		logrus.Warn("sysbox-fs caught signal: SIGTINT")

	case syscall.SIGTERM:
		logrus.Warn("sysbox-fs caught signal: SIGTERM")

	case syscall.SIGQUIT:
		logrus.Warn("sysbox-fs caught signal: SIGQUIT")

	default:
		logrus.Warn("sysbox-fs caught unknown signal")
	}

	logrus.Warn(
		"Unmounting sysbox-fs from mountpoint ",
		fs.MountPoint(),
		". Exitting...",
	)

	fs.Unmount()

	// Deferring exit() to allow FUSE to dump unnmount() logs
	time.Sleep(2)

	os.Exit(0)
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
			Name:  "dentry-cache-timeout, t",
			Value: fuse.DentryCacheTimeout,
			Usage: "dentry-cache-timeout timer in minutes",
			Destination: &fuse.DentryCacheTimeout,
		},
	}

	// show-version specialization.
	cli.VersionPrinter = func(c *cli.Context) {
		fmt.Printf("sysbox-fs\n" +
			"\tversion: \t%s\n" +
			"\tcommit: \t%s\n" +
			"\tbuilt at: \t%s\n" +
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
				logrus.Fatalf("Error opening log file %v: %v", path, err)
				return err
			}

			// Set a proper logging formatter.
			logrus.SetFormatter(&logrus.TextFormatter{
				ForceColors: true,
				TimestampFormat : "2006-01-02 15:04:05",
				FullTimestamp: true,
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
				logrus.Panicf("'%v' log-level option not recognized", logLevel)
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
		if fuseService == nil {
			log.Panic("FuseService initialization error")
		}

		// TODO: Consider adding sync.Workgroups to ensure that all goroutines
		// are done with their in-fly tasks before exit()ing.

		// Launch signal-handler to ensure mountpoint is properly unmounted
		// if an actionable signal is ever received.
		var signalChan = make(chan os.Signal)
		signal.Notify(
			signalChan,
			syscall.SIGHUP,
			syscall.SIGINT,
			syscall.SIGTERM,
			syscall.SIGSEGV,
			syscall.SIGQUIT)
		go signalHandler(signalChan, fuseService)

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
