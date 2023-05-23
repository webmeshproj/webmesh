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
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
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

// Options are the node options.
type Options struct {
	Global    *global.Options    `yaml:"global" json:"global" toml:"global"`
	Store     *StoreOptions      `yaml:"store" json:"store" toml:"store"`
	GRPC      *services.Options  `yaml:"grpc" json:"grpc" toml:"grpc"`
	Wireguard *wireguard.Options `yaml:"wireguard" json:"wireguard" toml:"wireguard"`
}

type StoreOptions struct {
	*store.Options `yaml:",inline" json:",inline" toml:",inline"`
	StreamLayer    *streamlayer.Options `yaml:"stream-layer" json:"stream-layer" toml:"stream-layer"`
}

// BindFlags binds the flags.
func (o *Options) BindFlags(fs *flag.FlagSet) {
	o.Global.BindFlags(fs)
	o.Store.BindFlags(fs)
	o.Store.StreamLayer.BindFlags(fs)
	o.GRPC.BindFlags(fs)
	o.Wireguard.BindFlags(fs)
}

var (
	versionFlag = flag.Bool("version", false, "Print version information and exit")
	configFlag  = flag.String("config", "", "Path to a configuration file")
	printConfig = flag.Bool("print-config", false, "Print the configuration and exit")

	opts = &Options{
		Global: global.NewOptions(),
		Store: &StoreOptions{
			Options:     store.NewOptions(),
			StreamLayer: streamlayer.NewOptions(),
		},
		GRPC:      services.NewOptions(),
		Wireguard: wireguard.NewOptions(),
	}

	log = slog.Default()
	st  store.Store
)

func init() {
	opts.BindFlags(flag.CommandLine)
	flag.Usage = usage
	flag.Parse()
	opts.Global.Overlay(
		opts.Store,
		opts.Store.StreamLayer,
		opts.GRPC,
		opts.Wireguard,
	)
}

func main() {
	if *versionFlag {
		fmt.Println("Webmesh Node")
		fmt.Println("  Version:   ", version.Version)
		fmt.Println("  Commit:    ", version.Commit)
		fmt.Println("  Build Date:", version.BuildDate)
		os.Exit(0)
	}

	if *configFlag != "" {
		f, err := os.Open(*configFlag)
		if err != nil {
			fatal("failed to open configuration file", err)
		}
		err = util.DecodeOptions(f, filepath.Ext(*configFlag), opts)
		if err != nil {
			fatal("failed to decode configuration file", err)
		}
	}

	if *printConfig {
		out, err := json.MarshalIndent(opts, "", "  ")
		if err != nil {
			fatal("failed to marshal configuration", err)
		}
		fmt.Println(string(out))
		os.Exit(0)
	}

	if !opts.Store.Bootstrap && opts.Store.Join == "" {
		if _, err := os.Stat(opts.Store.DataDir); os.IsNotExist(err) {
			flag.Usage()
			fmt.Fprintln(os.Stderr, "ERROR: Must specify either --store.bootstrap or --store.join when --store.data-dir does not exist")
			os.Exit(1)
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
		fatal("cannot disable both IPv4 and IPv6", nil)
	}

	var err error

	// Validate options
	err = opts.Store.StreamLayer.Validate()
	if err != nil {
		fatal("failed to validate stream layer options", err)
	}

	// Validate remaining options
	err = opts.Store.Validate()
	if err != nil {
		fatal("failed to validate store options", err)
	}

	log.Info("starting raft node")

	// Create the stream layer
	sl, err := streamlayer.New(opts.Store.StreamLayer)
	if err != nil {
		fatal("failed to create stream layer", err)
	}

	// Create and open the store
	st = store.New(sl, opts.Store.Options, opts.Wireguard)
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
	srv, err := services.NewServer(st, opts.GRPC)
	if err != nil {
		fatal("failed to create gRPC server", err)
	}

	// Always register the node server
	log.Debug("registering node server")
	features := []v1.Feature{v1.Feature_NODES}
	if opts.GRPC.EnableMetrics {
		features = append(features, v1.Feature_METRICS_GRPC)
	}
	if !opts.GRPC.DisableLeaderProxy {
		features = append(features, v1.Feature_LEADER_PROXY)
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
	util.FlagsUsage("gRPC Server Configurations:", "grpc", "")
	util.FlagsUsage("WireGuard Configurations:", "wireguard", "")

	fmt.Fprint(os.Stderr, "General Flags\n\n")
	fmt.Fprintf(os.Stderr, "  --config         Load flags from the given configuration file\n")
	fmt.Fprintf(os.Stderr, "  --print-config   Print the configuration and exit\n")
	fmt.Fprintf(os.Stderr, "\n")
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
