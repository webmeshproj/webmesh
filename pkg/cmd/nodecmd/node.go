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
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/pflag"

	"github.com/webmeshproj/webmesh/pkg/cmd/bridgecmd"
	"github.com/webmeshproj/webmesh/pkg/cmd/config"
	nodedaemon "github.com/webmeshproj/webmesh/pkg/cmd/nodedamon"
	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/mesh"
	"github.com/webmeshproj/webmesh/pkg/services"
	"github.com/webmeshproj/webmesh/pkg/util/logutil"
	"github.com/webmeshproj/webmesh/pkg/version"
)

var (
	flagset                 = pflag.NewFlagSet("webmesh-node", pflag.ContinueOnError)
	helpFlag                = flagset.Bool("help", false, "Print usage information and exit")
	versionFlag             = flagset.Bool("version", false, "Print version information and exit")
	configFlag              = flagset.String("config", "", "Path to a configuration file")
	printConfig             = flagset.Bool("print-config", false, "Print the configuration and exit")
	startTimeout            = flagset.Duration("start-timeout", 0, "Timeout for starting the node (default: no timeout)")
	shutdownTimeout         = flagset.Duration("shutdown-timeout", 0, "Timeout for shutting down the node (default: no timeout)")
	appDaemon               = flagset.Bool("app-daemon", false, "Run the node as an application daemon (default: false)")
	appDaemonBind           = flagset.String("app-daemon-bind", "", "Address to bind the application daemon to (default: unix:///var/run/webmesh-node.sock)")
	appDaemonGrpcWeb        = flagset.Bool("app-daemon-grpc-web", false, "Use gRPC-Web for the application daemon (default: false)")
	appDaemonInsecureSocket = flagset.Bool("app-daemon-insecure-socket", false, "Leave default ownership on the Unix socket (default: false)")
)

func Execute() error {
	// Parse flags and read in configurations
	conf := &config.Config{}
	conf.BindFlags("", flagset)
	err := flagset.Parse(os.Args[1:])
	if err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			return nil
		}
		return err
	}

	if *helpFlag {
		fmt.Fprint(os.Stderr, Usage(flagset))
		return nil
	}

	// Dump the version and exit
	if *versionFlag {
		fmt.Println("Webmesh Node")
		fmt.Println("  Version:   ", version.Version)
		fmt.Println("  Commit:    ", version.Commit)
		fmt.Println("  Build Date:", version.BuildDate)
		return nil
	}

	// Load the configuration
	var configs []string
	if *configFlag != "" {
		configs = append(configs, *configFlag)
	}
	err = conf.LoadFrom(flagset, configs)
	if err != nil {
		return err
	}

	// Dump the config and exit
	if *printConfig {
		out, err := json.MarshalIndent(conf, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(out))
		return nil
	}

	// Apply globals
	conf, err = conf.Global.ApplyGlobals(conf)
	if err != nil {
		return err
	}

	// Validate the configuration
	if !*appDaemon {
		err = conf.Validate()
		if err != nil {
			if errors.Is(err, config.ErrNoMesh) {
				// Display usage if no mesh is configured
				fmt.Fprint(os.Stderr, Usage(flagset))
				fmt.Fprintln(os.Stderr, "No mesh configured")
				os.Exit(1)
			}
			return err
		}
	}

	// Time to get going

	log := logutil.SetupLogging(conf.Global.LogLevel)
	ctx := context.WithLogger(context.Background(), log)

	log.Info("Starting webmesh node",
		slog.String("version", version.Version),
		slog.String("commit", version.Commit),
		slog.String("buildDate", version.BuildDate),
	)

	// Log all options at debug level
	dump, err := json.Marshal(conf)
	if err != nil {
		return err
	}
	out := map[string]interface{}{}
	err = json.Unmarshal(dump, &out)
	if err != nil {
		return err
	}
	log.Debug("Current configuration", slog.Any("options", out))

	if *startTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *startTimeout)
		defer cancel()
	}

	if *appDaemon {
		return nodedaemon.Run(context.Background(), nodedaemon.Config{
			Bind:           *appDaemonBind,
			InsecureSocket: *appDaemonInsecureSocket,
			GRPCWeb:        *appDaemonGrpcWeb,
			Config:         conf,
		})
	}

	if len(conf.Bridge.Meshes) > 0 {
		return bridgecmd.RunBridgeConnection(ctx, conf.Bridge)
	}
	return runMeshConnection(ctx, conf)
}

func runMeshConnection(ctx context.Context, config *config.Config) error {
	if config.Mesh.DisableIPv4 && config.Mesh.DisableIPv6 {
		return fmt.Errorf("cannot disable both IPv4 and IPv6")
	}
	log := context.LoggerFrom(ctx)
	log.Info("Starting mesh node")
	// Create a new mesh connection
	meshConfig, err := config.NewMeshConfig(ctx)
	if err != nil {
		return fmt.Errorf("failed to create mesh config: %w", err)
	}
	meshConn := mesh.New(meshConfig)
	// Create a new raft node
	raftNode, err := config.NewRaftNode(meshConn)
	if err != nil {
		return fmt.Errorf("failed to create raft node: %w", err)
	}
	startOpts, err := config.NewRaftStartOptions(meshConn)
	if err != nil {
		return fmt.Errorf("failed to create raft start options: %w", err)
	}
	connectOpts, err := config.NewConnectOptions(ctx, meshConn, raftNode)
	if err != nil {
		return fmt.Errorf("failed to create connect options: %w", err)
	}
	// Start the raft node
	err = raftNode.Start(ctx, startOpts)
	if err != nil {
		return fmt.Errorf("failed to start raft node: %w", err)
	}
	// Connect to the mesh
	err = meshConn.Connect(ctx, connectOpts)
	if err != nil {
		defer func() {
			err := raftNode.Stop(context.Background())
			if err != nil {
				log.Error("failed to shutdown raft node", slog.String("error", err.Error()))
			}
		}()
		return fmt.Errorf("failed to open mesh connection: %w", err)
	}
	select {
	case <-meshConn.Ready():
	case <-ctx.Done():
		return fmt.Errorf("failed to start mesh node: %w", ctx.Err())
	}

	// If anything goes wrong at this point, make sure we close down cleanly.
	handleErr := func(cause error) error {
		if err := meshConn.Close(); err != nil {
			log.Error("failed to shutdown mesh", slog.String("error", err.Error()))
		}
		return fmt.Errorf("failed to start mesh node: %w", cause)
	}
	log.Info("Mesh connection is ready, starting services")

	// Start the mesh services
	srvOpts, err := config.NewServiceOptions(ctx, meshConn)
	if err != nil {
		return handleErr(fmt.Errorf("failed to create service options: %w", err))
	}
	srv, err := services.NewServer(srvOpts)
	if err != nil {
		return handleErr(fmt.Errorf("failed to create gRPC server: %w", err))
	}
	err = config.RegisterAPIs(ctx, meshConn, srv)
	if err != nil {
		return handleErr(fmt.Errorf("failed to register APIs: %w", err))
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			err = handleErr(err)
			log.Error("Mesh services failed", slog.String("error", err.Error()))
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
		if err = meshConn.Close(); err != nil {
			log.Error("failed to shutdown mesh connection", slog.String("error", err.Error()))
		}
	}()

	// Stop the gRPC server
	log.Info("Shutting down mesh services")
	if *shutdownTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), *shutdownTimeout)
		defer cancel()
	}
	srv.Shutdown(ctx)
	return nil
}
