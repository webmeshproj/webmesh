/*
Copyright 2023.

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

// Entrypoint for webmesh nodes.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	v1 "gitlab.com/webmesh/api/v1"
	"golang.org/x/exp/slog"

	"gitlab.com/webmesh/node/pkg/global"
	"gitlab.com/webmesh/node/pkg/services"
	"gitlab.com/webmesh/node/pkg/services/node"
	"gitlab.com/webmesh/node/pkg/store"
	"gitlab.com/webmesh/node/pkg/store/streamlayer"
	"gitlab.com/webmesh/node/pkg/util"
	"gitlab.com/webmesh/node/pkg/version"
	"gitlab.com/webmesh/node/pkg/wireguard"
)

var (
	versionFlag = flag.Bool("version", false, "Print version information and exit")
	globalOpts  = global.NewOptions()
	wgOpts      = wireguard.NewOptions()
	storeOpts   = store.NewOptions()
	slOpts      = streamlayer.NewOptions()
	svcOpts     = services.NewOptions()
	log         = slog.Default()
	st          store.Store
)

func init() {
	globalOpts.BindFlags(flag.CommandLine)
	storeOpts.BindFlags(flag.CommandLine)
	slOpts.BindFlags(flag.CommandLine)
	svcOpts.BindFlags(flag.CommandLine)
	wgOpts.BindFlags(flag.CommandLine)
	flag.Usage = usage
	flag.Parse()
	globalOpts.Overlay(storeOpts, slOpts, svcOpts, wgOpts)
}

func main() {
	if *versionFlag {
		fmt.Println("Webmesh Node")
		fmt.Println("  Version:   ", version.Version)
		fmt.Println("  Commit:    ", version.Commit)
		fmt.Println("  Build Date:", version.BuildDate)
		os.Exit(0)
	}

	if !storeOpts.Bootstrap && storeOpts.Join == "" {
		if _, err := os.Stat(storeOpts.DataDir); os.IsNotExist(err) {
			flag.Usage()
			fmt.Fprintln(os.Stderr, "ERROR: Must specify either --store.bootstrap or --store.join when --store.data-dir does not exist")
			os.Exit(1)
		}
	}

	log = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: func() slog.Level {
			switch strings.ToLower(globalOpts.LogLevel) {
			case "debug":
				return slog.LevelDebug
			case "info":
				return slog.LevelInfo
			case "warn":
				return slog.LevelWarn
			case "error":
				return slog.LevelError
			default:
				return slog.LevelInfo
			}
		}(),
	}))
	slog.SetDefault(log)

	log.Info("starting webmesh node",
		slog.String("version", version.Version),
		slog.String("commit", version.Commit),
		slog.String("buildDate", version.BuildDate),
	)

	// Log all options at debug level
	log.Debug("options",
		slog.Any("store", storeOpts),
		slog.Any("streamLayer", slOpts),
		slog.Any("services", svcOpts),
		slog.Any("wireguard", wgOpts),
	)

	if (globalOpts.NoIPv4 && globalOpts.NoIPv6) || (storeOpts.NoIPv4 && storeOpts.NoIPv6) {
		fatal("cannot disable both IPv4 and IPv6", nil)
	}

	var err error

	// Validate options
	err = slOpts.Validate()
	if err != nil {
		fatal("failed to validate stream layer options", err)
	}

	// Validate remaining options
	err = storeOpts.Validate()
	if err != nil {
		fatal("failed to validate store options", err)
	}

	log.Info("starting raft node")

	// Create the stream layer
	sl, err := streamlayer.New(slOpts)
	if err != nil {
		fatal("failed to create stream layer", err)
	}

	// Create and open the store
	st = store.New(sl, storeOpts, wgOpts)
	err = st.Open()
	if err != nil {
		fatal("failed to open store", err)
	}

	log.Info("waiting for raft store to become ready")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	<-st.ReadyNotify(ctx)
	if ctx.Err() != nil {
		fatal("failed to wait for raft store to become ready", ctx.Err())
	}
	cancel()
	if err := <-st.ReadyError(); err != nil {
		// Only applicable during an initial bootstrap
		fatal("failed to wait for raft store to become ready", err)
	}
	// Shutdown the store on exit
	defer func() {
		log.Info("shutting down raft store")
		if err = st.Close(context.Background()); err != nil {
			fatal("failed to close raft store", err)
		}
	}()
	log.Info("raft store is ready, starting services")

	// Create the services
	srv, err := services.NewServer(st, svcOpts)
	if err != nil {
		fatal("failed to create gRPC server", err)
	}

	// Always register the node server
	log.Debug("registering node server")
	features := []v1.Feature{v1.Feature_NODES}
	if svcOpts.EnableMetrics {
		features = append(features, v1.Feature_METRICS_GRPC)
	}
	v1.RegisterNodeServer(srv, node.NewServer(st, features...))

	// Start the gRPC server
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			fatal("failed to start gRPC server", err)
		}
	}()

	// Wait for shutdown signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	// Stop the gRPC server
	log.Info("shutting down gRPC server")
	srv.Stop()
}

func usage() {
	fmt.Fprint(os.Stderr, "Webmesh Node\n\n")
	fmt.Fprintf(os.Stderr, "Usage: %s [flags]\n", os.Args[0])
	fmt.Fprint(os.Stderr, "\n")

	util.FlagsUsage("Global Configurations", "global", "")
	util.FlagsUsage("Raft Store Configurations", "store", "store.stream-layer")
	util.FlagsUsage("Raft Stream Layer Configurations", "store.stream-layer", "")
	util.FlagsUsage("gRPC Server Configurations", "grpc", "")
	util.FlagsUsage("WireGuard Configurations", "wireguard", "")

	fmt.Fprint(os.Stderr, "General Flags\n\n")
	fmt.Fprintf(os.Stderr, "  --help       Show this help message\n")
	fmt.Fprintf(os.Stderr, "  --version    Show version information and exit\n")
	fmt.Fprint(os.Stderr, "\n")
}

func fatal(msg string, err error) {
	if st != nil && st.IsOpen() {
		if err := st.Close(context.Background()); err != nil {
			log.Error("failed to close store",
				slog.String("error", err.Error()))
		}
	}
	if err != nil {
		log.Error(fmt.Sprintf("FATAL: %s", msg), slog.String("error", err.Error()))
	} else {
		log.Error(fmt.Sprintf("FATAL: %s", msg))
	}
	os.Exit(1)
}
