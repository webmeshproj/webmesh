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
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/multiformats/go-multiaddr"
	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/cmd/nodecmd/options"
	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/mesh"
	"github.com/webmeshproj/webmesh/pkg/meshbridge"
	"github.com/webmeshproj/webmesh/pkg/net/transport"
	"github.com/webmeshproj/webmesh/pkg/net/transport/grpc"
	"github.com/webmeshproj/webmesh/pkg/net/transport/libp2p"
	"github.com/webmeshproj/webmesh/pkg/net/transport/tcp"
	"github.com/webmeshproj/webmesh/pkg/services"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/nutsdb"
	"github.com/webmeshproj/webmesh/pkg/util"
	"github.com/webmeshproj/webmesh/pkg/util/logutil"
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
	config := options.NewOptions().BindFlags(flagset)
	flagset.Usage = func() {
		options.Usage(flagset)
	}
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

	log := logutil.SetupLogging(config.Global.LogLevel)
	ctx := context.Background()

	if !*appDaemon {
		if err := config.Validate(); err != nil {
			flagset.Usage()
			return err
		}
	}

	log.Info("Starting webmesh node",
		slog.String("version", version.Version),
		slog.String("commit", version.Commit),
		slog.String("buildDate", version.BuildDate),
	)

	// Log all options at debug level
	dump, err := json.Marshal(config)
	if err != nil {
		return err
	}
	out := map[string]interface{}{}
	err = json.Unmarshal(dump, &out)
	if err != nil {
		return err
	}
	log.Debug("Current configuration", slog.Any("options", out))

	if *appDaemon {
		return RunAppDaemon(ctx, config)
	}

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

func executeSingleMesh(ctx context.Context, config *options.Options) error {
	if (config.Global.NoIPv4 && config.Global.NoIPv6) || (config.Mesh.Mesh.NoIPv4 && config.Mesh.Mesh.NoIPv6) {
		return fmt.Errorf("cannot disable both IPv4 and IPv6")
	}
	log := slog.Default()

	// Create a new mesh node
	st, err := mesh.New(config.Mesh)
	if err != nil {
		return fmt.Errorf("failed to create mesh connection: %w", err)
	}
	// Create a raft transport
	raftTransport, err := tcp.NewRaftTransport(st, tcp.RaftTransportOptions{
		Addr:    config.Mesh.Raft.ListenAddress,
		MaxPool: config.Mesh.Raft.ConnectionPoolCount,
		Timeout: config.Mesh.Raft.ConnectionTimeout,
	})
	if err != nil {
		return fmt.Errorf("failed to create raft transport: %w", err)
	}
	// Create the raft storage
	var storage storage.DualStorage
	if config.Mesh.Raft.InMemory {
		storage, err = nutsdb.New(nutsdb.Options{InMemory: true})
		if err != nil {
			return fmt.Errorf("create in-memory storage: %w", err)
		}
	} else {
		storage, err = nutsdb.New(nutsdb.Options{
			DiskPath: config.Mesh.Raft.DataStoragePath(),
		})
		if err != nil {
			return fmt.Errorf("create raft storage: %w", err)
		}
	}
	var features []v1.Feature
	if !config.Global.DisableFeatureAdvertisement {
		isRaftMember := func() bool {
			if config.Mesh.Bootstrap != nil && config.Mesh.Bootstrap.Enabled {
				return true
			}
			if config.Mesh.Mesh != nil {
				return config.Mesh.Mesh.JoinAsVoter || config.Mesh.Mesh.JoinAsObserver
			}
			return false
		}()
		features = config.Services.ToFeatureSet(isRaftMember)
	}
	// Determine our join transport
	joinTransport, err := getJoinTransport(ctx, st, config)
	if err != nil {
		return fmt.Errorf("failed to create join transport: %w", err)
	}
	var bootstrapTransport transport.BootstrapTransport
	var forceBootstrap bool
	if config.Mesh.Bootstrap != nil && config.Mesh.Bootstrap.Enabled {
		forceBootstrap = config.Mesh.Bootstrap.Force
		bootstrapTransport = newBootstrapTransport(ctx, st, config)
	}
	err = st.Open(ctx, mesh.ConnectOptions{
		Features:           features,
		BootstrapTransport: bootstrapTransport,
		JoinRoundTripper:   joinTransport,
		RaftTransport:      raftTransport,
		RaftStorage:        storage,
		MeshStorage:        storage,
		ForceBootstrap:     forceBootstrap,
	})
	if err != nil {
		return fmt.Errorf("failed to open mesh connection: %w", err)
	}
	select {
	case <-st.Ready():
	case <-ctx.Done():
		return fmt.Errorf("failed to start mesh node: %w", ctx.Err())
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

func executeBridgedMesh(ctx context.Context, config *options.Options) error {
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

func getJoinTransport(ctx context.Context, st mesh.Mesh, config *options.Options) (transport.JoinRoundTripper, error) {
	var joinTransport transport.JoinRoundTripper
	if config.Mesh.Bootstrap != nil && config.Mesh.Bootstrap.Enabled {
		// Our join transport is the gRPC transport to other bootstrap nodes
		var addrs []string
		for id, addr := range config.Mesh.Bootstrap.Servers {
			if id == st.ID() {
				continue
			}
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("invalid bootstrap server address: %w", err)
			}
			var addr string
			if len(config.Mesh.Bootstrap.ServersGRPCPorts) > 0 && config.Mesh.Bootstrap.ServersGRPCPorts[host] != 0 {
				addr = fmt.Sprintf("%s:%d", host, config.Mesh.Bootstrap.ServersGRPCPorts[host])
			} else {
				// Assume the default port
				addr = fmt.Sprintf("%s:%d", host, mesh.DefaultGRPCPort)
			}
			addrs = append(addrs, addr)
		}
		joinTransport = grpc.NewJoinRoundTripper(grpc.JoinOptions{
			Addrs:          addrs,
			Credentials:    st.Credentials(ctx),
			AddressTimeout: time.Second * 3,
		})
	} else if config.Mesh.Mesh.JoinAddress != "" {
		joinTransport = grpc.NewJoinRoundTripper(grpc.JoinOptions{
			Addrs:          []string{config.Mesh.Mesh.JoinAddress},
			Credentials:    st.Credentials(ctx),
			AddressTimeout: time.Second * 3,
		})
	} else if config.Mesh.Discovery != nil && config.Mesh.Discovery.UseKadDHT {
		var addrs []multiaddr.Multiaddr
		for _, addr := range config.Mesh.Discovery.KadBootstrapServers {
			maddr, err := multiaddr.NewMultiaddr(addr)
			if err != nil {
				return nil, fmt.Errorf("invalid bootstrap peer address: %w", err)
			}
			addrs = append(addrs, maddr)
		}
		joinTransport = libp2p.NewDHTJoinRoundTripper(libp2p.DHTJoinOptions{
			PSK:            config.Mesh.Discovery.PSK,
			BootstrapPeers: addrs,
			ConnectTimeout: time.Second * 3,
		})
	}
	// A nil transport is technically okay, it means we are a single-node mesh
	return joinTransport, nil
}

func newBootstrapTransport(ctx context.Context, st mesh.Mesh, config *options.Options) transport.BootstrapTransport {
	if len(config.Mesh.Bootstrap.Servers) == 0 {
		return transport.NewNullBootstrapTransport()
	}
	return tcp.NewBootstrapTransport(tcp.BootstrapTransportOptions{
		NodeID:          st.ID(),
		Addr:            config.Mesh.Bootstrap.ListenAddress,
		Advertise:       config.Mesh.Bootstrap.AdvertiseAddress,
		MaxPool:         config.Mesh.Raft.ConnectionPoolCount,
		Timeout:         config.Mesh.Raft.ConnectionTimeout,
		ElectionTimeout: config.Mesh.Raft.ElectionTimeout,
		Credentials:     st.Credentials(ctx),
		Peers: func() map[string]tcp.BootstrapPeer {
			if config.Mesh.Bootstrap.Servers == nil {
				return nil
			}
			peers := make(map[string]tcp.BootstrapPeer)
			for id, addr := range config.Mesh.Bootstrap.Servers {
				if id == st.ID() {
					continue
				}
				nodeID := id
				nodeAddr := addr
				nodeHost, _, err := net.SplitHostPort(nodeAddr)
				if err != nil {
					// We should have caught this earlier
					context.LoggerFrom(ctx).Warn("Encountered invalid bootstrap server address",
						slog.String("address", nodeAddr), slog.String("error", err.Error()))
					continue
				}
				// Deterine what their join address will be
				var joinAddr string
				if port, ok := config.Mesh.Bootstrap.ServersGRPCPorts[nodeID]; ok {
					joinAddr = net.JoinHostPort(nodeHost, fmt.Sprintf("%d", port))
				} else {
					// Assume the default gRPC port
					joinAddr = net.JoinHostPort(nodeHost, fmt.Sprintf("%d", mesh.DefaultGRPCPort))
				}
				peers[nodeID] = tcp.BootstrapPeer{
					NodeID:        nodeID,
					AdvertiseAddr: nodeAddr,
					DialAddr:      joinAddr,
				}
			}
			return peers
		}(),
	})
}
