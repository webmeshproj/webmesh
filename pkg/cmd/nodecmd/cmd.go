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

// Package nodecmd contains the entrypoint for webmesh nodes.
package nodecmd

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	v1 "github.com/webmeshproj/api/v1"
	"golang.org/x/exp/slog"

	"github.com/webmeshproj/webmesh/pkg/mesh"
	"github.com/webmeshproj/webmesh/pkg/services"
	"github.com/webmeshproj/webmesh/pkg/util"
	"github.com/webmeshproj/webmesh/pkg/version"
)

var (
	fs          = flag.NewFlagSet("node", flag.ContinueOnError)
	versionFlag = fs.Bool("version", false, "Print version information and exit")
	configFlag  = fs.String("config", "", "Path to a configuration file")
	printConfig = fs.Bool("print-config", false, "Print the configuration and exit")
	opts        = NewOptions().BindFlags(fs)

	log = slog.Default()
)

func Execute() error {
	fs.Usage = usage
	err := fs.Parse(os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	if *versionFlag {
		fmt.Println("Webmesh Node")
		fmt.Println("  Version:   ", version.Version)
		fmt.Println("  Commit:    ", version.Commit)
		fmt.Println("  Build Date:", version.BuildDate)
		return nil
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

	err = opts.Global.Overlay(opts.Mesh, opts.Services)
	if err != nil {
		return err
	}

	if *printConfig {
		out, err := json.MarshalIndent(opts, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(out))
		return nil
	}

	if !opts.Mesh.Bootstrap.Enabled && opts.Mesh.Mesh.JoinAddress == "" {
		if _, err := os.Stat(opts.Mesh.Raft.DataDir); os.IsNotExist(err) {
			if !opts.Mesh.Raft.InMemory {
				fs.Usage()
				return fmt.Errorf("must specify either --bootstrap.enabled or --mesh.join-address when --raft.data-dir does not exist")
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

	if (opts.Global.NoIPv4 && opts.Global.NoIPv6) || (opts.Mesh.Mesh.NoIPv4 && opts.Mesh.Mesh.NoIPv6) {
		return fmt.Errorf("cannot disable both IPv4 and IPv6")
	}

	// Create and open the store
	st, err := mesh.New(opts.Mesh)
	if err != nil {
		return fmt.Errorf("failed to create mesh store: %w", err)
	}

	// TODO: Add flag for timeout
	ctx := context.Background()
	var features []v1.Feature
	if !opts.Global.DisableFeatureAdvertisement {
		features = opts.Services.ToFeatureSet()
	}
	err = st.Open(ctx, features)
	if err != nil {
		return fmt.Errorf("failed to open mesh store: %w", err)
	}
	handleErr := func(cause error) error {
		if err := st.Close(); err != nil {
			log.Error("failed to shutdown mesh store", slog.String("error", err.Error()))
		}
		return fmt.Errorf("failed to start mesh node: %w", cause)
	}
	// Shutdown the store on exit
	defer func() {
		log.Info("shutting down mesh store")
		if err = st.Close(); err != nil {
			log.Error("failed to shutdown mesh store", slog.String("error", err.Error()))
		}
	}()
	log.Info("mesh store is ready, starting services")

	// Create the services
	srv, err := services.NewServer(st, opts.Services)
	if err != nil {
		return handleErr(fmt.Errorf("failed to create gRPC server: %w", err))
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
