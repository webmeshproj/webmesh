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
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/mesh"
	"github.com/webmeshproj/webmesh/pkg/meshbridge"
	"github.com/webmeshproj/webmesh/pkg/services"
	"github.com/webmeshproj/webmesh/pkg/util"
	"github.com/webmeshproj/webmesh/pkg/version"
)

var (
	flagset                 = flag.NewFlagSet("webmesh-node", flag.ContinueOnError)
	versionFlag             = flagset.Bool("version", false, "Print version information and exit")
	configFlag              = flagset.String("config", "", "Path to a configuration file")
	printConfig             = flagset.Bool("print-config", false, "Print the configuration and exit")
	startTimeout            = flagset.Duration("start-timeout", 0, "Timeout for starting the node (default: no timeout)")
	appDaemon               = flagset.Bool("app-daemon", false, "Run the node as an application daemon (default: false)")
	appDaemonBind           = flagset.String("app-daemon-bind", "", "Address to bind the application daemon to (default: unix:///var/run/webmesh-node.sock)")
	appDaemonGrpcWeb        = flagset.Bool("app-daemon-grpc-web", false, "Use gRPC-Web for the application daemon (default: false)")
	appDaemonInsecureSocket = flagset.Bool("app-daemon-insecure-socket", false, "Leave default ownership on the Unix socket (default: false)")
)

func Execute() error {
	// Parse flags and read in configurations

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
		err = util.DecodeOptions(f, filepath.Ext(*configFlag), config)
		if err != nil {
			return fmt.Errorf("failed to decode config file: %w", err)
		}
	}
	err = config.Global.Overlay(config.Mesh, config.Services, config.Bridge)
	if err != nil {
		return err
	}
	if *printConfig {
		// Dump the config and exit
		out, err := json.MarshalIndent(config, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(out))
		return nil
	}

	// Time to get going

	log := util.SetupLogging(config.Global.LogLevel)
	ctx := context.Background()

	if *appDaemon {
		return RunAppDaemon(ctx, config)
	}

	if err := config.Validate(); err != nil {
		flagset.Usage()
		return err
	}

	log.Info("Starting webmesh node",
		slog.String("version", version.Version),
		slog.String("commit", version.Commit),
		slog.String("buildDate", version.BuildDate),
	)

	// Log all options at debug level
	log.Debug("Current configuration", slog.Any("options", config))

	if *startTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *startTimeout)
		defer cancel()
	}

	if len(config.Bridge.Meshes) > 0 {
		return executeBridgedMesh(ctx, config)
	}
	return executeSingleMesh(ctx, config)
}

func executeSingleMesh(ctx context.Context, config *Options) error {
	if (config.Global.NoIPv4 && config.Global.NoIPv6) || (config.Mesh.Mesh.NoIPv4 && config.Mesh.Mesh.NoIPv6) {
		return fmt.Errorf("cannot disable both IPv4 and IPv6")
	}
	log := slog.Default()

	// Connect to the mesh
	st, err := mesh.New(config.Mesh)
	if err != nil {
		return fmt.Errorf("failed to create mesh connection: %w", err)
	}
	var features []v1.Feature
	if !config.Global.DisableFeatureAdvertisement {
		features = config.Services.ToFeatureSet()
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
	log.Info("Mesh connection is ready, starting services")

	// Start the mesh services
	srv, err := services.NewServer(st, config.Services)
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
		log.Info("Shutting down mesh connection")
		if err = st.Close(); err != nil {
			log.Error("failed to shutdown mesh connection", slog.String("error", err.Error()))
		}
	}()

	// Stop the gRPC server
	log.Info("Shutting down gRPC server")
	srv.Stop()
	return nil
}

func executeBridgedMesh(ctx context.Context, config *Options) error {
	log := slog.Default()
	br, err := meshbridge.New(config.Bridge)
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
