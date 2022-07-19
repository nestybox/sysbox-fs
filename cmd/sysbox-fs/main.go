//
// Copyright 2019-2020 Nestybox, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
	"github.com/nestybox/sysbox-fs/handler"
	"github.com/nestybox/sysbox-fs/ipc"
	"github.com/nestybox/sysbox-fs/mount"
	"github.com/nestybox/sysbox-fs/nsenter"
	"github.com/nestybox/sysbox-fs/process"
	"github.com/nestybox/sysbox-fs/seccomp"
	"github.com/nestybox/sysbox-fs/state"
	"github.com/nestybox/sysbox-fs/sysio"
	libutils "github.com/nestybox/sysbox-libs/utils"

	systemd "github.com/coreos/go-systemd/daemon"

	"github.com/pkg/profile"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

const (
	sysboxRunDir    string = "/run/sysbox"
	sysboxFsPidFile string = sysboxRunDir + "/sysfs.pid"
	usage           string = `sysbox-fs file-system

sysbox-fs is a daemon that emulates portions of the system container's
file system (e.g., procfs, sysfs). It's purpose is to make the
system container closely resemble a virtual host while ensuring
proper isolation.
`
)

// Globals to be populated at build time during Makefile processing.
var (
	edition  string // Sysbox Edition: CE or EE.
	version  string // extracted from VERSION file
	commitId string // latest sysbox-fs' git commit-id
	builtAt  string // build time
	builtBy  string // build owner
)

//
// sysbox-fs exit handler goroutine.
//
func exitHandler(
	signalChan chan os.Signal,
	fss domain.FuseServerServiceIface,
	profile interface{ Stop() }) {

	var printStack = false

	s := <-signalChan

	logrus.Warnf("sysbox-fs caught signal: %s", s)

	logrus.Info("Stopping (gracefully) ...")

	systemd.SdNotify(false, systemd.SdNotifyStopping)

	switch s {

	case syscall.SIGABRT:
		printStack = true

	case syscall.SIGINT:
		printStack = true

	case syscall.SIGQUIT:
		printStack = true

	case syscall.SIGSEGV:
		printStack = true
	}

	if printStack {
		// Buffer size = 1024 x 32, enough to hold every goroutine stack-trace.
		stacktrace := make([]byte, 32768)
		length := runtime.Stack(stacktrace, true)
		logrus.Warnf("\n\n%s\n", string(stacktrace[:length]))
	}

	// Destroy fuse-service and inner fuse-servers.
	fss.DestroyFuseService()

	// Stop cpu/mem profiling tasks.
	if profile != nil {
		profile.Stop()
	}

	// Deferring exit() to allow FUSE to dump unnmount() logs
	time.Sleep(2)

	// Delete pid file.
	if err := libutils.DestroyPidFile(sysboxFsPidFile); err != nil {
		logrus.Warnf("failed to destroy sysbox-fs pid file: %v", err)
	}

	logrus.Info("Exiting ...")
	os.Exit(0)
}

// Run cpu / memory profiling collection.
func runProfiler(ctx *cli.Context) (interface{ Stop() }, error) {

	var prof interface{ Stop() }

	cpuProfOn := ctx.Bool("cpu-profiling")
	memProfOn := ctx.Bool("memory-profiling")

	// Cpu and Memory profiling options seem to be mutually exclused in pprof.
	if cpuProfOn && memProfOn {
		return nil, fmt.Errorf("Unsupported parameter combination: cpu and memory profiling")
	}

	// Typical / non-profiling case.
	if !(cpuProfOn || memProfOn) {
		return nil, nil
	}

	// Notice that 'NoShutdownHook' option is passed to profiler constructor to
	// avoid this one reacting to 'sigterm' signal arrival. IOW, we want
	// sysbox-fs signal handler to be the one stopping all profiling tasks.

	if cpuProfOn {
		prof = profile.Start(
			profile.CPUProfile,
			profile.ProfilePath("."),
			profile.NoShutdownHook,
		)
	}

	if memProfOn {
		prof = profile.Start(
			profile.MemProfile,
			profile.ProfilePath("."),
			profile.NoShutdownHook,
		)
	}

	return prof, nil
}

func setupRunDir() error {
	if err := os.MkdirAll(sysboxRunDir, 0700); err != nil {
		return fmt.Errorf("failed to create %s: %s", sysboxRunDir, err)
	}
	return nil
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
		cli.BoolFlag{
			Name:  "allow-immutable-remounts",
			Usage: "sys container's initial mounts are considered immutable; this option allows them to be remounted from within the container (default: \"false\")",
		},
		cli.BoolTFlag{
			Name:  "allow-immutable-unmounts",
			Usage: "sys container's initial mounts are considered immutable; this option allows them to be unmounted from within the container (default: \"true\")",
		},
		cli.StringFlag{
			Name:  "seccomp-fd-release",
			Value: "proc-exit",
			Usage: "Policy to close syscall interception handles; allowed values are \"proc-exit\" and \"cont-exit\" (default = \"proc-exit\")",
		},
		cli.StringFlag{
			Name:  "log",
			Value: "",
			Usage: "log file path or empty string for stderr output (default: \"\")",
		},
		cli.StringFlag{
			Name:  "log-level",
			Value: "info",
			Usage: "log categories to include (debug, info, warning, error, fatal)",
		},
		cli.StringFlag{
			Name:  "log-format",
			Value: "text",
			Usage: "log format; must be json or text",
		},
		cli.BoolFlag{
			Name:   "ignore-handler-errors",
			Usage:  "ignore errors during procfs / sysfs node interactions (testing purposes)",
			Hidden: true,
		},
		cli.BoolFlag{
			Name:   "cpu-profiling",
			Usage:  "enable cpu-profiling data collection",
			Hidden: true,
		},
		cli.BoolFlag{
			Name:   "memory-profiling",
			Usage:  "enable memory-profiling data collection",
			Hidden: true,
		},
	}

	// show-version specialization.
	cli.VersionPrinter = func(c *cli.Context) {
		fmt.Printf("sysbox-fs\n"+
			"\tedition: \t%s\n"+
			"\tversion: \t%s\n"+
			"\tcommit: \t%s\n"+
			"\tbuilt at: \t%s\n"+
			"\tbuilt by: \t%s\n",
			edition, c.App.Version, commitId, builtAt, builtBy)
	}

	// Nsenter command to allow 'rexec' functionality.
	app.Commands = []cli.Command{
		{
			Name:  "nsenter",
			Usage: "Execute action within container namespaces",
			Action: func(c *cli.Context) error {
				// nsenter errors are passed back to sysbox-fs via a pipe
				nsenter.Init()
				return nil
			},
		},
	}

	// Define 'debug' and 'log' settings.
	app.Before = func(ctx *cli.Context) error {

		// Random generator seed
		rand.Seed(time.Now().UnixNano())

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

			logrus.SetOutput(f)
			log.SetOutput(f)
		} else {
			logrus.SetOutput(os.Stderr)
			log.SetOutput(os.Stderr)
		}

		if logFormat := ctx.GlobalString("log-format"); logFormat == "json" {
			logrus.SetFormatter(&logrus.JSONFormatter{
				TimestampFormat: "2006-01-02 15:04:05",
			})
		} else {
			logrus.SetFormatter(&logrus.TextFormatter{
				TimestampFormat: "2006-01-02 15:04:05",
				FullTimestamp:   true,
			})
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

		logrus.Info("Initiating sysbox-fs ...")

		err := libutils.CheckPidFile("sysbox-fs", sysboxFsPidFile)
		if err != nil {
			return err
		}

		// Print key configuration knobs settings.
		if ctx.BoolT("allow-immutable-remounts") {
			logrus.Info("Initializing with 'allow-immutable-remounts' enabled")
		} else {
			logrus.Info("Initializing with 'allow-immutable-remounts' knob disabled (default)")
		}
		if ctx.Bool("allow-immutable-unmounts") {
			logrus.Info("Initializing with 'allow-immutable-unmounts' knob enabled (default)")
		} else {
			logrus.Info("Initializing with 'allow-immutable-unmounts' knob disabled")
		}
		if ctx.GlobalString("seccomp-fd-release") == "cont-exit" {
			logrus.Info("Seccomp-notify fd release policy set to container exit")
		}
		logrus.Infof("FUSE dir = %s", ctx.GlobalString("mountpoint"))

		// Construct sysbox-fs services.
		var nsenterService = nsenter.NewNSenterService()
		var ioService = sysio.NewIOService(domain.IOOsFileService)
		var processService = process.NewProcessService()
		var handlerService = handler.NewHandlerService()
		var fuseServerService = fuse.NewFuseServerService()
		var containerStateService = state.NewContainerStateService()
		var syscallMonitorService = seccomp.NewSyscallMonitorService()
		var ipcService = ipc.NewIpcService()
		var mountService = mount.NewMountService()

		// Create the sysbox run dir
		err = setupRunDir()
		if err != nil {
			return fmt.Errorf("failed to setup the sysbox run dir: %v", err)
		}

		// Setup sysbox-fs services.
		processService.Setup(ioService)

		nsenterService.Setup(processService, nil)

		handlerService.Setup(
			handler.DefaultHandlers,
			ctx.Bool("ignore-handler-errors"),
			containerStateService,
			nsenterService,
			processService,
			ioService,
		)

		if err := fuseServerService.Setup(
			ctx.GlobalString("mountpoint"),
			containerStateService,
			ioService,
			handlerService,
		); err != nil {
			return err
		}

		containerStateService.Setup(
			fuseServerService,
			processService,
			ioService,
			mountService,
		)

		mountService.Setup(
			containerStateService,
			handlerService,
			processService,
			nsenterService,
		)

		syscallMonitorService.Setup(
			nsenterService,
			containerStateService,
			processService,
			mountService,
			ctx.BoolT("allow-immutable-remounts"),
			ctx.Bool("allow-immutable-unmounts"),
			ctx.GlobalString("seccomp-fd-release"),
		)

		ipcService.Setup(
			containerStateService,
			processService,
			ioService,
			ctx.GlobalString("mountpoint"),
		)

		// If requested, launch cpu/mem profiling collection.
		profile, err := runProfiler(ctx)
		if err != nil {
			logrus.Fatal(err)
		}

		// Launch exit handler (performs proper cleanup of sysbox-fs upon
		// receiving termination signals).
		var exitChan = make(chan os.Signal, 1)
		signal.Notify(
			exitChan,
			syscall.SIGHUP,
			syscall.SIGINT,
			syscall.SIGTERM,
			syscall.SIGSEGV,
			syscall.SIGQUIT)
		go exitHandler(exitChan, fuseServerService, profile)

		// TODO: Consider adding sync.Workgroups to ensure that all goroutines
		// are done with their in-fly tasks before exit()ing.

		systemd.SdNotify(false, systemd.SdNotifyReady)

		// Create sysbox-fs pid file.
		err = libutils.CreatePidFile("sysbox-fs", sysboxFsPidFile)
		if err != nil {
			return fmt.Errorf("failed to create sysfs.pid file: %s", err)
		}

		logrus.Info("Ready ...")

		if err := ipcService.Init(); err != nil {
			logrus.Errorf("failed to start sysbox-fs: %v", err)
		}

		// Exited main event-loop. Delete pid file.
		if err := libutils.DestroyPidFile(sysboxFsPidFile); err != nil {
			logrus.Warnf("failed to destroy sysbox-fs pid file: %v", err)
		}
		logrus.Info("Done.")

		return nil
	}

	if err := app.Run(os.Args); err != nil {
		logrus.Fatal(err)
	}
}
