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
	"github.com/webmeshproj/webmesh/pkg/meshbridge"
	"github.com/webmeshproj/webmesh/pkg/services"
	"github.com/webmeshproj/webmesh/pkg/util"
	"github.com/webmeshproj/webmesh/pkg/version"
)

var (
	flagset      = flag.NewFlagSet("webmesh-node", flag.ContinueOnError)
	versionFlag  = flagset.Bool("version", false, "Print version information and exit")
	configFlag   = flagset.String("config", "", "Path to a configuration file")
	printConfig  = flagset.Bool("print-config", false, "Print the configuration and exit")
	startTimeout = flagset.Duration("start-timeout", 0, "Timeout for starting the node (default: no timeout)")
	opts         = NewOptions().BindFlags(flagset)

	log = slog.Default()
)

func Execute() error {
	flagset.Usage = usage
	err := flagset.Parse(os.Args[1:])
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
	if err := opts.Validate(); err != nil {
		flagset.Usage()
		return err
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

	ctx := context.Background()
	if *startTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *startTimeout)
		defer cancel()
	}

	if len(opts.Bridge.Meshes) > 0 {
		return executeBridgedMesh(ctx)
	}
	return executeSingleMesh(ctx)
}

func executeSingleMesh(ctx context.Context) error {
	if (opts.Global.NoIPv4 && opts.Global.NoIPv6) || (opts.Mesh.Mesh.NoIPv4 && opts.Mesh.Mesh.NoIPv6) {
		return fmt.Errorf("cannot disable both IPv4 and IPv6")
	}

	// Connect to the mesh
	st, err := mesh.New(opts.Mesh)
	if err != nil {
		return fmt.Errorf("failed to create mesh connection: %w", err)
	}
	var features []v1.Feature
	if !opts.Global.DisableFeatureAdvertisement {
		features = opts.Services.ToFeatureSet()
	}
	err = st.Open(ctx, features)
	if err != nil {
		return fmt.Errorf("failed to open mesh connection: %w", err)
	}
	handleErr := func(cause error) error {
		if err := st.Close(); err != nil {
			log.Error("failed to shutdown mesh", slog.String("error", err.Error()))
		}
		return fmt.Errorf("failed to start mesh node: %w", cause)
	}
	log.Info("mesh connection is ready, starting services")

	// Start the mesh services
	srv, err := services.NewServer(st, opts.Services)
	if err != nil {
		return handleErr(fmt.Errorf("failed to create gRPC server: %w", err))
	}
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

	// Shutdown the mesh connection last
	defer func() {
		log.Info("shutting down mesh connection")
		if err = st.Close(); err != nil {
			log.Error("failed to shutdown mesh connection", slog.String("error", err.Error()))
		}
	}()

	// Stop the gRPC server
	log.Info("shutting down gRPC server")
	srv.Stop()
	return nil
}

func executeBridgedMesh(ctx context.Context) error {
	br, err := meshbridge.New(opts.Bridge)
	if err != nil {
		return fmt.Errorf("failed to create mesh bridge: %w", err)
	}
	err = br.Start(ctx)
	if err != nil {
		return fmt.Errorf("failed to start mesh bridge: %w", err)
	}
	defer func() {
		err := br.Stop(context.Background())
		if err != nil {
			log.Error("failed to shutdown mesh bridge", slog.String("error", err.Error()))
		}
	}()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case <-sig:
		return nil
	case err := <-br.ServeError():
		return fmt.Errorf("mesh bridge failed: %w", err)
	}
}
