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

// Package bridgecmd contains the entrypoint for running a bridge
// between multiple clusters.
package bridgecmd

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc"

	"github.com/webmeshproj/webmesh/pkg/config"
	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/meshnet/system/dns"
	"github.com/webmeshproj/webmesh/pkg/meshnode"
	"github.com/webmeshproj/webmesh/pkg/services"
	"github.com/webmeshproj/webmesh/pkg/services/meshdns"
)

func RunBridgeConnection(ctx context.Context, config config.BridgeOptions) error {
	if runtime.GOOS == "windows" {
		return fmt.Errorf("bridge mode is not supported on windows")
	}
	log := context.LoggerFrom(ctx)

	// Build all the mesh objects.
	meshes := make(map[string]meshnode.Node)
	for meshID, meshConfig := range config.Meshes {
		id := meshID
		// For now we only allow IPv6 on bridged meshes.
		meshConfig.Mesh.DisableIPv4 = true
		// We handle DNS on the bridge level only.
		meshConfig.Mesh.MeshDNSAdvertisePort = 0
		meshConfig.Mesh.UseMeshDNS = false
		meshConfig.Services.MeshDNS.Enabled = false
		// Create a new mesh connection
		meshConfig, err := meshConfig.NewMeshConfig(ctx, nil)
		if err != nil {
			return fmt.Errorf("failed to create mesh config: %w", err)
		}
		meshConn := meshnode.NewWithLogger(log.With("mesh-id", id), meshConfig)
		meshes[id] = meshConn
	}

	cleanFuncs := make([]func(), 0, len(meshes))
	handleErr := func(cause error) error {
		for _, clean := range cleanFuncs {
			clean()
		}
		return fmt.Errorf("failed to start bridge: %w", cause)
	}

	// Start all the mesh connections.
	for meshID, meshConn := range meshes {
		// Create a new raft node and build connection options
		meshConfig := config.Meshes[meshID]
		storageProvider, err := meshConfig.NewStorageProvider(ctx, meshConn, meshConfig.Bootstrap.Force)
		if err != nil {
			return handleErr(fmt.Errorf("failed to create storage provider: %w", err))
		}
		connectOpts, err := meshConfig.NewConnectOptions(ctx, meshConn, storageProvider, nil)
		if err != nil {
			return handleErr(fmt.Errorf("failed to create connect options: %w", err))
		}
		// Start the storage provider
		err = storageProvider.Start(ctx)
		if err != nil {
			return handleErr(fmt.Errorf("failed to start storage provider: %w", err))
		}
		cleanFuncs = append(cleanFuncs, func() {
			err := storageProvider.Close()
			if err != nil {
				log.Error("failed to shutdown raft node", slog.String("error", err.Error()))
			}
		})
		// Connect to the mesh
		err = meshConn.Connect(ctx, connectOpts)
		if err != nil {
			return handleErr(fmt.Errorf("failed to open mesh connection: %w", err))
		}
		cleanFuncs = append(cleanFuncs, func() {
			err := meshConn.Close(ctx)
			if err != nil {
				log.Error("failed to shutdown mesh", slog.String("error", err.Error()))
			}
		})
	}

	// Start all the mesh services
	errs := make(chan error, len(meshes)+1)
	meshSvcs := make(map[string]*services.Server)
	for meshID, meshConn := range meshes {
		id := meshID
		meshConfig := config.Meshes[id]
		srvOpts, err := meshConfig.Services.NewServiceOptions(ctx, meshConn)
		if err != nil {
			return handleErr(fmt.Errorf("failed to create service options: %w", err))
		}
		srv, err := services.NewServer(ctx, srvOpts)
		if err != nil {
			return handleErr(fmt.Errorf("failed to create gRPC server: %w", err))
		}
		if !meshConfig.Services.API.Disabled {
			features := meshConfig.Services.NewFeatureSet(meshConn.Storage(), meshConfig.Services.API.ListenPort())
			err = meshConfig.Services.RegisterAPIs(ctx, meshConn, srv, features)
			if err != nil {
				return handleErr(fmt.Errorf("failed to register APIs: %w", err))
			}
		}
		go func() {
			if err := srv.ListenAndServe(); err != nil {
				log.Error("Mesh services failed", slog.String("error", err.Error()))
				errs <- err
			}
		}()
		meshSvcs[id] = srv
	}

	// Wait for all the mesh connections to be ready
	for _, meshConn := range meshes {
		select {
		case <-meshConn.Ready():
		case <-ctx.Done():
			return handleErr(fmt.Errorf("failed to start bridge: %w", ctx.Err()))
		}
	}

	// Set up bridge DNS if enabled
	var dnsPort int
	if config.MeshDNS.Enabled {
		// Determine the DNS port
		if config.MeshDNS.ListenUDP != "" {
			_, port, err := net.SplitHostPort(config.MeshDNS.ListenUDP)
			if err != nil {
				return handleErr(fmt.Errorf("failed to parse meshdns listen UDP address: %w", err))
			}
			dnsPort, err = strconv.Atoi(port)
			if err != nil {
				return handleErr(fmt.Errorf("failed to parse meshdns listen UDP port: %w", err))
			}
		}
		dnsSrv := meshdns.NewServer(ctx, &meshdns.Options{
			UDPListenAddr:     config.MeshDNS.ListenUDP,
			TCPListenAddr:     config.MeshDNS.ListenTCP,
			ReusePort:         config.MeshDNS.ReusePort,
			Compression:       config.MeshDNS.EnableCompression,
			RequestTimeout:    config.MeshDNS.RequestTimeout,
			Forwarders:        config.MeshDNS.Forwarders,
			CacheSize:         config.MeshDNS.CacheSize,
			DisableForwarding: false,
		})
		// Register each mesh to the server
		for meshID, meshConn := range meshes {
			err := dnsSrv.RegisterDomain(meshdns.DomainOptions{
				NodeID:              meshConn.ID(),
				MeshDomain:          meshConn.Domain(),
				MeshStorage:         meshConn.Storage(),
				IPv6Only:            true,
				SubscribeForwarders: false,
			})
			if err != nil {
				return handleErr(fmt.Errorf("failed to register mesh %q with meshdns: %w", meshID, err))
			}
		}
		// Start the DNS server
		go func() {
			if err := dnsSrv.ListenAndServe(); err != nil {
				log.Error("MeshDNS server failed", slog.String("error", err.Error()))
				errs <- err
			}
		}()
		defer func() {
			if err := dnsSrv.Shutdown(context.Background()); err != nil {
				log.Error("MeshDNS server failed to shutdown", slog.String("error", err.Error()))
			}
		}()
		// If we are enabling MeshDNS locally, set the system resolvers
		if config.UseMeshDNS {
			addrport := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(dnsPort))
			err := dns.AddServers("", []netip.AddrPort{addrport})
			if err != nil {
				// Make this non-fatal for now
				log.Error("Failed to set system DNS servers", slog.String("error", err.Error()))
			} else {
				// Remove the server when we shutdown
				defer func() {
					err := dns.RemoveServers("", []netip.AddrPort{addrport})
					if err != nil {
						log.Error("Failed to remove system DNS servers", slog.String("error", err.Error()))
					}
				}()
			}
		}
	}

	// Last but not least, dial each mesh and tell them about the other meshes.
	for meshID, meshConn := range meshes {
		var toBroadcast []string
		for otherID, otherMesh := range meshes {
			if otherID != meshID {
				toBroadcast = append(toBroadcast, otherMesh.Network().NetworkV6().String())
			}
			// TODO: Check if any unique non-internal routes are broadcasted
			// by the other meshes and add them to this list (per a configuration flag).
			// Will need to subscribe to route updates from the other meshes.
			meshConfig := config.Meshes[otherID]
			req := &v1.UpdateRequest{
				Id:     meshConn.ID().String(),
				Routes: toBroadcast,
				Features: meshConfig.Services.NewFeatureSet(
					meshConn.Storage(),
					meshConfig.Services.API.ListenPort(),
				),
			}
			// If we are bridging DNS, add it to our feature set
			if config.MeshDNS.Enabled {
				req.Features = append(req.Features, &v1.FeaturePort{
					Feature: v1.Feature_MESH_DNS,
					Port:    int32(dnsPort),
				}, &v1.FeaturePort{
					Feature: v1.Feature_FORWARD_MESH_DNS,
					Port:    int32(dnsPort),
				})
			}
			log.Info("Broadcasting routes and features to mesh", slog.String("mesh-id", meshID))
			// Make retries configurable
			var tries int
			var maxTries int = 5
			var err error
		UpdateRetry:
			for tries <= maxTries {
				if ctx.Err() != nil {
					return handleErr(fmt.Errorf("timed out starting up mesh bridge: %w", ctx.Err()))
				}
				var c *grpc.ClientConn
				c, err = meshConn.DialLeader(ctx)
				if err != nil {
					tries++
					log.Error("Failed to dial mesh leader", slog.String("error", err.Error()))
					time.Sleep(time.Second)
					continue
				}
				defer c.Close()
				_, err = v1.NewMembershipClient(c).Update(ctx, req)
				if err != nil {
					tries++
					log.Error("Failed to send update RPC to mesh leader", slog.String("error", err.Error()))
					time.Sleep(time.Second)
					continue
				}
				break UpdateRetry
			}
			if err != nil {
				return handleErr(fmt.Errorf("failed to send update RPC to mesh leader: %w", err))
			}
		}
	}

	// All done, wait for errors or a signal.
	log.Info("Mesh bridge is ready")

	// Make sure we close mesh connections last
	defer func() {
		for id, meshConn := range meshes {
			log.Info("Shutting down mesh connection", slog.String("mesh-id", id))
			err := meshConn.Close(ctx)
			if err != nil {
				log.Error("Failed to shutdown mesh connection", slog.String("error", err.Error()))
			}
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case <-sig:
	case err := <-errs:
		return err
	}

	// Shutdown all the mesh services
	var wg sync.WaitGroup
	for id, srv := range meshSvcs {
		wg.Add(1)
		go func(id string, srv *services.Server) {
			log.Info("Shutting down mesh services", slog.String("mesh-id", id))
			srv.Shutdown(context.Background())
			wg.Done()
		}(id, srv)
	}
	wg.Wait()
	return nil
}
