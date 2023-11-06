//go:build windows

/*
Copyright 2023 Avi Zimmerman <avi.zimmerman@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/spf13/pflag"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"

	"github.com/webmeshproj/webmesh/pkg/cmd/daemoncmd"
)

const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

var elog debug.Log

func run() {
	var err error
	elog, err = eventlog.Open("webmeshd")
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to open event log:", err)
		return
	}
	defer elog.Close()
	logInfo("Starting webmesh daemon helper")
	err = svc.Run("webmeshd", &helperDaemon{})
	if err != nil {
		logError("Failed to start helper daemon", err)
		return
	}
	logInfo("Webmesh daemon helper stopped")
}

func logError(msg string, err error) {
	msg = fmt.Sprintf("%s: %v", msg, err)
	fmt.Fprintln(os.Stderr, msg)
	if elog != nil {
		elog.Error(1, msg)
	}
}

func logInfo(msg string) {
	fmt.Fprintln(os.Stdout, msg)
	if elog != nil {
		elog.Info(1, msg)
	}
}

type helperDaemon struct{}

func (d *helperDaemon) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	var err error
	changes <- svc.Status{State: svc.StartPending}

	flagset := pflag.NewFlagSet("webmeshd", pflag.ContinueOnError)
	config := daemoncmd.NewDefaultConfig().BindFlags("daemon.", flagset)
	err = flagset.Parse(args[1:])
	if err != nil {
		logError("Failed to parse service arguments", err)
		errno = 1
		return
	}

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errs := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		logInfo("Starting webmesh daemon")
		if err := daemoncmd.Run(ctx, *config); err != nil {
			errs <- err
		}
	}()
	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

EventLoop:
	for {
		select {
		case err := <-errs:
			logError("Daemon exited with error", err)
			errno = 2
			return
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				logInfo("Received stop request, shutting down")
				cancel()
				break EventLoop
			default:
				logError("Unexpected service control request", fmt.Errorf("cmd=%d", c.Cmd))
			}
		}
	}
	changes <- svc.Status{State: svc.StopPending}
	wg.Wait()
	return
}
