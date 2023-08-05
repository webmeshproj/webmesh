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

// Package meshbridge contains a wrapper interface for running multiple mesh connections
// in parallel and sharing routes between them.
package meshbridge

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"time"

	v1 "github.com/webmeshproj/api/v1"
	"golang.org/x/exp/slog"

	"github.com/webmeshproj/webmesh/pkg/mesh"
	"github.com/webmeshproj/webmesh/pkg/net/system/dns"
	"github.com/webmeshproj/webmesh/pkg/services"
	"github.com/webmeshproj/webmesh/pkg/services/meshdns"
)

// Bridge is the interface for a mesh bridge. It manages multiple mesh connections
// and services, sharing routes between them.
type Bridge interface {
	// Start starts the bridge. This opens all meshes and services.
	Start(ctx context.Context) error
	// Stop stops the bridge. This closes all meshes and services.
	Stop(ctx context.Context) error
	// ServeError returns a channel that will receive an error if any gRPC server
	// fails.
	ServeError() <-chan error
	// Mesh returns the mesh with the given ID. If ID is an invalid mesh ID,
	// nil is returned.
	Mesh(id string) mesh.Mesh
}

// New creates a new bridge.
func New(opts *Options) (Bridge, error) {
	if runtime.GOOS == "windows" {
		return nil, fmt.Errorf("bridge mode is not supported on windows")
	}
	err := opts.Validate()
	if err != nil {
		return nil, err
	}
	meshes := make(map[string]mesh.Mesh)
	for meshID, meshOpts := range opts.Meshes {
		id := meshID
		// For now we only allow IPv6 on bridged meshes.
		meshOpts.Mesh.Mesh.NoIPv4 = true
		// We handle DNS on the bridge level only.
		meshOpts.Mesh.Mesh.MeshDNSAdvertisePort = 0
		meshOpts.Mesh.Mesh.UseMeshDNS = false
		meshOpts.Services.MeshDNS = nil
		m, err := mesh.NewWithLogger(meshOpts.Mesh, slog.Default().With("mesh-id", id))
		if err != nil {
			return nil, fmt.Errorf("failed to create mesh %q: %w", id, err)
		}
		meshes[id] = m
	}
	errBuf := len(meshes)
	if opts.MeshDNS != nil && opts.MeshDNS.Enabled {
		errBuf++
	}
	return &meshBridge{
		opts:    opts,
		meshes:  meshes,
		servers: make(map[string]*services.Server, len(meshes)),
		srvErrs: make(chan error, errBuf),
		log:     slog.Default().With("component", "meshbridge"),
	}, nil
}

type meshBridge struct {
	opts      *Options
	meshes    map[string]mesh.Mesh
	servers   map[string]*services.Server
	meshdns   *meshdns.Server
	systemdns []netip.AddrPort
	srvErrs   chan error
	log       *slog.Logger
}

// Mesh returns the mesh with the given ID.
func (m *meshBridge) Mesh(id string) mesh.Mesh {
	return m.meshes[id]
}

// ServerError returns a channel that will receive an error if any gRPC server
// fails.
func (m *meshBridge) ServeError() <-chan error {
	return m.srvErrs
}

// Start starts the bridge. This opens all meshes and services.
func (m *meshBridge) Start(ctx context.Context) error {
	cleanFuncs := make([]func(), 0, len(m.meshes))
	handleErr := func(cause error) error {
		for _, clean := range cleanFuncs {
			clean()
		}
		return fmt.Errorf("failed to start bridge: %w", cause)
	}
	// Start all the mesh connections
	for id, meshOpts := range m.opts.Meshes {
		meshID := id
		features := meshOpts.Services.ToFeatureSet()
		// Open the mesh connection
		m.log.Info("opening mesh", slog.String("mesh-id", meshID))
		mesh := m.Mesh(meshID)
		if mesh == nil {
			// This should never happen
			return handleErr(fmt.Errorf("mesh %q not found", meshID))
		}
		err := mesh.Open(ctx, features)
		if err != nil {
			return handleErr(fmt.Errorf("failed to open mesh %q: %w", meshID, err))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-mesh.Ready():
		}
		cleanFuncs = append(cleanFuncs, func() {
			err := mesh.Close()
			if err != nil {
				m.log.Error("failed to close mesh", slog.String("mesh-id", meshID), slog.String("error", err.Error()))
			}
		})
		// Create the services for this mesh
		m.log.Info("starting mesh services", slog.String("mesh-id", meshID))
		srv, err := services.NewServer(mesh, meshOpts.Services)
		if err != nil {
			return handleErr(fmt.Errorf("failed to create gRPC server: %w", err))
		}
		m.servers[meshID] = srv
		// Start the services
		go func() {
			if err := srv.ListenAndServe(); err != nil {
				m.log.Error("gRPC server failed", slog.String("mesh-id", meshID), slog.String("error", err.Error()))
				m.srvErrs <- err
			}
		}()
	}
	// Start a MeshDNS server if enabled
	if m.opts.MeshDNS != nil && m.opts.MeshDNS.Enabled {
		m.meshdns = meshdns.NewServer(&meshdns.Options{
			UDPListenAddr:     m.opts.MeshDNS.ListenUDP,
			TCPListenAddr:     m.opts.MeshDNS.ListenTCP,
			ReusePort:         m.opts.MeshDNS.ReusePort,
			Compression:       m.opts.MeshDNS.EnableCompression,
			RequestTimeout:    m.opts.MeshDNS.RequestTimeout,
			Forwarders:        m.opts.MeshDNS.Forwarders,
			DisableForwarding: m.opts.MeshDNS.DisableForwarding,
			CacheSize:         m.opts.MeshDNS.CacheSize,
		})
		for _, mesh := range m.meshes {
			ms := mesh
			err := m.meshdns.RegisterDomain(meshdns.DomainOptions{
				Mesh:     ms,
				IPv6Only: true,
			})
			if err != nil {
				return handleErr(fmt.Errorf("failed to register mesh %q with meshdns: %w", ms.ID(), err))
			}
		}
		go func() {
			if err := m.meshdns.ListenAndServe(); err != nil {
				m.log.Error("meshdns server failed", slog.String("error", err.Error()))
				m.srvErrs <- err
			}
		}()
	}
	var dnsport uint16
	if m.opts.MeshDNS != nil && m.opts.MeshDNS.Enabled {
		_, udpPort, err := net.SplitHostPort(m.opts.MeshDNS.ListenUDP)
		if err != nil {
			// Should have never passed validate
			return fmt.Errorf("failed to parse meshdns udp listen address: %w", err)
		}
		zport, err := strconv.ParseUint(udpPort, 10, 16)
		if err != nil {
			// Should have never passed validate
			return fmt.Errorf("failed to parse meshdns udp listen port: %w", err)
		}
		dnsport = uint16(zport)
	}
	if m.opts.UseMeshDNS {
		addrport := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), dnsport)
		err := dns.AddServers("", []netip.AddrPort{addrport})
		if err != nil {
			// Make this non-fatal for now
			m.log.Warn("failed to add meshdns server to system dns", slog.String("error", err.Error()))
		} else {
			m.systemdns = append(m.systemdns, addrport)
		}
	}
	// We need to dial each mesh's leader and tell them we can route the other
	// meshes.
	for meshID, mesh := range m.meshes {
		var toBroadcast []string
		for otherID, otherMesh := range m.meshes {
			if otherID != meshID {
				toBroadcast = append(toBroadcast, otherMesh.Network().NetworkV6().String())
			}
		}
		// TODO: Check if any unique non-internal routes are broadcasted
		// by the other meshes and add them to this list (per a configuration flag).
		// Will need to subscribe to route updates from the other meshes.
		req := &v1.UpdateRequest{
			Id:     mesh.ID(),
			Routes: toBroadcast,
		}
		if m.opts.MeshDNS != nil && m.opts.MeshDNS.Enabled {
			// Tell the leader we can do forwarded meshdns now also
			currentFeats := m.opts.Meshes[meshID].Services.ToFeatureSet()
			req.Features = append(currentFeats, v1.Feature_MESH_DNS, v1.Feature_FORWARD_MESH_DNS)
			req.MeshdnsPort = int32(dnsport)
		}
		m.log.Info("broadcasting routes and features to mesh", slog.String("mesh-id", meshID), slog.Any("request", req))
		var tries int
		// TODO: Make this configurable
		var maxTries = 5
		for tries <= maxTries {
			if ctx.Err() != nil {
				return fmt.Errorf("context canceled: %w", ctx.Err())
			}
			err := m.broadcastRoutesAndFeatures(ctx, mesh, req)
			if err == nil {
				break
			}
			m.log.Error("failed to broadcast routes and features", slog.String("mesh-id", meshID), slog.String("error", err.Error()))
			if tries >= maxTries {
				return handleErr(fmt.Errorf("broadcast routes and features for mesh %q: %w", meshID, err))
			}
			tries++
			time.Sleep(time.Second)
		}
	}
	return nil
}

func (m *meshBridge) broadcastRoutesAndFeatures(ctx context.Context, mesh mesh.Mesh, req *v1.UpdateRequest) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := mesh.DialLeader(ctx)
	if err != nil {
		return fmt.Errorf("dial leader: %w", err)
	}
	defer conn.Close()
	_, err = v1.NewNodeClient(conn).Update(ctx, req)
	if err != nil {
		return fmt.Errorf("broadcast updates: %w", err)
	}
	return nil
}

// Stop stops the bridge. This closes all meshes and services.
func (m *meshBridge) Stop(ctx context.Context) error {
	if len(m.systemdns) > 0 {
		err := dns.RemoveServers("", m.systemdns)
		if err != nil {
			m.log.Warn("failed to remove meshdns server from system dns", slog.String("error", err.Error()))
		}
	}
	if m.meshdns != nil {
		m.log.Info("shutting down meshdns server")
		err := m.meshdns.Shutdown()
		if err != nil {
			m.log.Warn("failed to shutdown meshdns server", slog.String("error", err.Error()))
		}
	}
	for meshID, srv := range m.servers {
		m.log.Info("shutting down gRPC server", slog.String("mesh-id", meshID))
		srv.Stop()
	}
	for meshID, mesh := range m.meshes {
		m.log.Info("shutting down mesh connection", slog.String("mesh-id", meshID))
		err := mesh.Close()
		if err != nil {
			slog.Default().Error("failed to close mesh", slog.String("mesh-id", meshID), slog.String("error", err.Error()))
		}
	}
	return nil
}
