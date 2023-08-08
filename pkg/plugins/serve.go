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

package plugins

import (
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc"

	"github.com/webmeshproj/webmesh/pkg/context"
)

// Serve is a convenience function for serving a plugin. It should be used
// by plugins that are intended to be run as a separate process.
func Serve(ctx context.Context, plugin v1.PluginServer) error {
	addr := flag.String("listen-address", "127.0.0.1:0", "address to listen on")
	broadcastFd := flag.Int("broadcast-fd", -1, "file descriptor to broadcast the address on")
	flag.Parse()
	log := slog.Default()
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	if *broadcastFd != -1 {
		log.Info("broadcasting address", "address", ln.Addr().String(), "fd", *broadcastFd)
		if err := broadcastAddress(*broadcastFd, ln.Addr().String()); err != nil {
			return err
		}
	}
	s := grpc.NewServer()
	v1.RegisterPluginServer(s, plugin)
	if storage, ok := plugin.(v1.StoragePluginServer); ok {
		log.Info("registering storage plugin")
		v1.RegisterStoragePluginServer(s, storage)
	}
	if auth, ok := plugin.(v1.AuthPluginServer); ok {
		log.Info("registering auth plugin")
		v1.RegisterAuthPluginServer(s, auth)
	}
	if watch, ok := plugin.(v1.WatchPluginServer); ok {
		log.Info("registering watch plugin")
		v1.RegisterWatchPluginServer(s, watch)
	}
	if ipam, ok := plugin.(v1.IPAMPluginServer); ok {
		log.Info("registering ipam plugin")
		v1.RegisterIPAMPluginServer(s, ipam)
	}
	log.Info("serving plugin", "address", ln.Addr().String())
	errs := make(chan error, 1)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		defer close(errs)
		if err := s.Serve(ln); err != nil {
			errs <- err
		}
	}()
	select {
	case <-ctx.Done():
		log.Info("shutting down plugin")
		_, err := plugin.Close(context.Background(), nil)
		if err != nil {
			log.Error("error closing plugin", "error", err.Error())
		}
		s.GracefulStop()
		return nil
	case <-sig:
		log.Info("shutting down plugin")
		_, err := plugin.Close(context.Background(), nil)
		if err != nil {
			log.Error("error closing plugin", "error", err.Error())
		}
		go func() {
			log.Info("waiting for plugin to shut down, press ctrl-c again to force")
			<-sig
			os.Exit(1)
		}()
		s.GracefulStop()
		return nil
	case err := <-errs:
		return err
	}
}

func broadcastAddress(fd int, addr string) error {
	f := os.NewFile(uintptr(fd), "broadcast")
	if f == nil {
		return fmt.Errorf("invalid file descriptor %d", fd)
	}
	defer f.Close()
	if _, err := f.WriteString(addr); err != nil {
		return err
	}
	return nil
}
