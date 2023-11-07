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

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"

	"github.com/webmeshproj/webmesh/pkg/cmd/daemoncmd"
	"github.com/webmeshproj/webmesh/pkg/logging"
)

func run() {
	elog, err := eventlog.Open("webmeshd")
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to open event log:", err)
		return
	}
	defer elog.Close()
	logInfo(elog, "Starting webmesh daemon helper")
	err = svc.Run("webmeshd", &helperDaemon{elog})
	if err != nil {
		logError(elog, "Failed to start helper daemon", err)
		return
	}
	logInfo(elog, "Webmesh daemon helper stopped")
}

func logError(elog debug.Log, msg string, err error) {
	msg = fmt.Sprintf("%s: %v", msg, err)
	fmt.Fprintln(os.Stderr, msg)
	if elog != nil {
		elog.Error(1, msg)
	}
}

func logInfo(elog debug.Log, msg string) {
	fmt.Fprintln(os.Stdout, msg)
	if elog != nil {
		elog.Info(1, msg)
	}
}

type helperDaemon struct {
	elog debug.Log
}

func (d *helperDaemon) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

	changes <- svc.Status{State: svc.StartPending}
	config := daemoncmd.NewDefaultConfig()
	config.Enabled = true
	config.GRPCWeb = true
	config.CORS.Enabled = true
	config.Bind = "127.0.0.1:58080"
	config.KeyFile = `C:\ProgramData\Webmesh\key`
	config.Persistence.Path = `C:\ProgramData\Webmesh`
	config.Logger = logging.NewServiceLogAdapter(d.elog, "info")
	logInfo(d.elog, fmt.Sprintf("Starting webmesh daemon with config: %+v", config))
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errs := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		logInfo(d.elog, "Starting webmesh daemon")
		if err := daemoncmd.Run(ctx, *config); err != nil {
			errs <- err
		}
	}()
	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

EventLoop:
	for {
		select {
		case err := <-errs:
			logError(d.elog, "Daemon exited with error", err)
			errno = 2
			return
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				logInfo(d.elog, "Received stop request, shutting down")
				cancel()
				break EventLoop
			default:
				logError(d.elog, "Unexpected service control request", fmt.Errorf("cmd=%d", c.Cmd))
			}
		}
	}
	changes <- svc.Status{State: svc.StopPending}
	wg.Wait()
	return
}
