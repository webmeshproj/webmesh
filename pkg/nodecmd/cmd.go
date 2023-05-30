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

// Package nodecmd contains the entrypoint for webmesh nodes.
package nodecmd

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/exp/slog"

	"github.com/webmeshproj/node/pkg/global"
	"github.com/webmeshproj/node/pkg/services"
	"github.com/webmeshproj/node/pkg/store"
	"github.com/webmeshproj/node/pkg/store/streamlayer"
	"github.com/webmeshproj/node/pkg/util"
	"github.com/webmeshproj/node/pkg/version"
	"github.com/webmeshproj/node/pkg/wireguard"
)

var (
	versionFlag = flag.Bool("version", false, "Print version information and exit")
	configFlag  = flag.String("config", "", "Path to a configuration file")
	printConfig = flag.Bool("print-config", false, "Print the configuration and exit")
	opts        = (&Options{
		Global: global.NewOptions(),
		Store: &StoreOptions{
			Options:     store.NewOptions(),
			StreamLayer: streamlayer.NewOptions(),
		},
		Services:  services.NewOptions(),
		Wireguard: wireguard.NewOptions(),
	}).BindFlags(flag.CommandLine)

	log = slog.Default()
)

func Execute() error {
	flag.Usage = usage
	flag.Parse()

	if *versionFlag {
		fmt.Println("Webmesh Node")
		fmt.Println("  Version:   ", version.Version)
		fmt.Println("  Commit:    ", version.Commit)
		fmt.Println("  Build Date:", version.BuildDate)
		return nil
	}

	err := opts.Global.Overlay(
		opts.Store.Options,
		opts.Store.StreamLayer,
		opts.Services,
		opts.Wireguard,
	)
	if err != nil {
		return err
	}

	if *configFlag != "" {
		f, err := os.Open(*configFlag)
		if err != nil {
			return fmt.Errorf("failed to open config file: %w", err)
		}
		err = util.DecodeOptions(f, filepath.Ext(*configFlag), opts)
		if err != nil {
			return fmt.Errorf("failed to decode config file: %w", err)
		}
	}

	if *printConfig {
		out, err := json.MarshalIndent(opts, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(out))
		return nil
	}

	if !opts.Store.Bootstrap && opts.Store.Join == "" {
		if _, err := os.Stat(opts.Store.DataDir); os.IsNotExist(err) {
			if !opts.Store.InMemory {
				flag.Usage()
				return fmt.Errorf("Must specify either --store.bootstrap or --store.join when --store.data-dir does not exist")
			}
		}
	}

	log = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: func() slog.Level {
			switch strings.ToLower(opts.Global.LogLevel) {
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
	log.Debug("current configuration", slog.Any("options", opts))

	if (opts.Global.NoIPv4 && opts.Global.NoIPv6) || (opts.Store.NoIPv4 && opts.Store.NoIPv6) {
		return fmt.Errorf("cannot disable both IPv4 and IPv6")
	}

	// Validate options
	err = opts.Store.StreamLayer.Validate()
	if err != nil {
		return fmt.Errorf("failed to validate stream layer options: %w", err)
	}
	err = opts.Store.Validate()
	if err != nil {
		return fmt.Errorf("failed to validate store options: %w", err)
	}
	err = opts.Wireguard.Validate()
	if err != nil {
		return fmt.Errorf("failed to validate wireguard options: %w", err)
	}
	err = opts.Services.Validate()
	if err != nil {
		return fmt.Errorf("failed to validate grpc options: %w", err)
	}

	log.Info("starting raft node")

	// Create the stream layer
	sl, err := streamlayer.New(opts.Store.StreamLayer)
	if err != nil {
		return fmt.Errorf("failed to create stream layer: %w", err)
	}

	// Create and open the store
	st := store.New(sl, opts.Store.Options, opts.Wireguard)
	err = st.Open()
	if err != nil {
		return fmt.Errorf("failed to open raft store: %w", err)
	}

	handleErr := func(cause error) error {
		if err := st.Close(); err != nil {
			log.Error("failed to shutdown raft store", slog.String("error", err.Error()))
		}
		return fmt.Errorf("failed to start raft node: %w", cause)
	}

	log.Info("waiting for raft store to become ready")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	<-st.ReadyNotify(ctx)
	if ctx.Err() != nil {
		defer cancel()
		return handleErr(fmt.Errorf("failed to wait for raft store to become ready: %w", ctx.Err()))
	}
	cancel()
	if err := <-st.ReadyError(); err != nil {
		// Only applicable during an initial bootstrap
		return handleErr(fmt.Errorf("failed to wait for raft store to become ready: %w", err))
	}
	// Shutdown the store on exit
	defer func() {
		log.Info("shutting down raft store")
		if err = st.Close(); err != nil {
			log.Error("failed to shutdown raft store", slog.String("error", err.Error()))
		}
	}()
	log.Info("raft store is ready, starting services")

	// Create the services
	srv, err := services.NewServer(st, opts.Services)
	if err != nil {
		return handleErr(fmt.Errorf("failed to gRPC server: %w", err))
	}

	// Start the gRPC server
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			err = handleErr(err)
			log.Error("gRPC server failed", slog.String("error", err.Error()))
			os.Exit(1)
		}
	}()

	// Wait for shutdown signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	// Stop the gRPC server
	log.Info("shutting down gRPC server")
	srv.Stop()

	return nil
}

func usage() {
	fmt.Fprintf(os.Stderr, "Webmesh Node (Version: %s)\n\n", version.Version)
	fmt.Fprintf(os.Stderr, "Usage: %s [flags]\n", os.Args[0])

	fmt.Fprint(os.Stderr, `
The webmesh node is a single node in a webmesh cluster. It is responsible for
tracking the cluster state, managing network configurations, and providing a 
gRPC API for other nodes to interact with the cluster. The API is also used by
the webmesh CLI to interact with the cluster.

The node can be configured to bootstrap a new cluster or join an existing
cluster. When bootstrapping a new cluster, the node will become the leader of
the cluster. When joining an existing cluster, the node will attempt to join
the cluster by contacting the leader. Optionally, the node can be configured to
bootstrap with a set of initial nodes. When bootstrapping with initial nodes,
the node will become the leader of the cluster if the initial nodes are not
already part of a cluster. If the initial nodes are already part of a cluster,
the node will join the cluster by contacting the leader of the cluster.

Configuration is available via command line flags, environment variables, and
configuration files. The configuration is parsed in the following order:

  - Environment Variables
  - Command Line Flags
  - Configuration File

Environment variables match the command line flags where all characters are
uppercased and dashes and dots are replaced with underscores. For example, the
command line flag "store.stream-layer.listen-address" would be set via the
environment variable "STORE_STREAM_LAYER_LISTEN_ADDRESS".

Configuration files can be in YAML, JSON, or TOML. The configuration file is
specified via the "--config" flag. The configuration file matches the structure 
of the command line flags. For example, the following YAML configuration would 
be equivalent to the shown command line flag:

  # config.yaml
  store:
    stream-layer:
      listen-address: 127.0.0.1  # --store.stream-layer.listen-address

`)

	util.FlagsUsage("Global Configurations:", "global", "")
	util.FlagsUsage("Raft Store Configurations:", "store", "store.stream-layer")
	util.FlagsUsage("Raft Stream Layer Configurations:", "store.stream-layer", "")
	util.FlagsUsage("Service Configurations:", "services", "")
	util.FlagsUsage("WireGuard Configurations:", "wireguard", "")

	fmt.Fprint(os.Stderr, "General Flags\n\n")
	fmt.Fprint(os.Stderr, "  --config         Load flags from the given configuration file\n")
	fmt.Fprint(os.Stderr, "  --print-config   Print the configuration and exit\n")
	fmt.Fprint(os.Stderr, "\n")
	fmt.Fprint(os.Stderr, "  --help       Show this help message\n")
	fmt.Fprint(os.Stderr, "  --version    Show version information and exit\n")
	fmt.Fprint(os.Stderr, "\n")
}
