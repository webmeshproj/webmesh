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

var elog debug.Log

const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

func run() {
	var err error
	elog, err = eventlog.Open("webmeshd")
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to open event log:", err)
		return
	}
	defer elog.Close()
	elog.Info(1, "Starting webmesh daemon helper")
	err = svc.Run("webmeshd", &helperDaemon{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to start helper daemon:", err)
		elog.Error(1, fmt.Sprintf("Webmesh daemon helper failed: %v", err))
		return
	}
	elog.Info(1, "Webmesh daemon helper stopped")
}

type helperDaemon struct{}

func (d *helperDaemon) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	var err error
	changes <- svc.Status{State: svc.StartPending}

	flagset := pflag.NewFlagSet("webmeshd", pflag.ContinueOnError)
	config := daemoncmd.NewDefaultConfig().BindFlags("daemon.", flagset)
	err = flagset.Parse(args)
	if err != nil {
		elog.Error(1, err.Error())
		return false, 1
	}

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errs := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := daemoncmd.Run(ctx, *config); err != nil {
			errs <- err
		}
	}()
	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

EventLoop:
	for {
		select {
		case err := <-errs:
			elog.Error(1, err.Error())
			return false, 1
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				elog.Info(1, "Received stop request, shutting down")
				cancel()
				break EventLoop
			default:
				elog.Error(1, fmt.Sprintf("Unexpected control request #%d", c))
			}
		}
	}
	changes <- svc.Status{State: svc.StopPending}
	wg.Wait()
	return
}
