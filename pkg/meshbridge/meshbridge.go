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

	"golang.org/x/exp/slog"

	"github.com/webmeshproj/webmesh/pkg/mesh"
	"github.com/webmeshproj/webmesh/pkg/services"
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
	err := opts.Validate()
	if err != nil {
		return nil, err
	}
	meshes := make(map[string]mesh.Mesh)
	for meshID, meshOpts := range opts.Meshes {
		id := meshID
		m, err := mesh.NewWithLogger(meshOpts.Mesh, slog.Default().With("mesh-id", id))
		if err != nil {
			return nil, fmt.Errorf("failed to create mesh %q: %w", id, err)
		}
		meshes[id] = m
	}
	return &meshBridge{
		opts:    opts,
		meshes:  meshes,
		servers: make(map[string]*services.Server, len(meshes)),
		srvErrs: make(chan error, len(meshes)),
		log:     slog.Default().With("component", "meshbridge"),
	}, nil
}

type meshBridge struct {
	opts    *Options
	meshes  map[string]mesh.Mesh
	servers map[string]*services.Server
	srvErrs chan error
	log     *slog.Logger
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
	for id, meshOpts := range m.opts.Meshes {
		meshID := id
		features := meshOpts.Services.ToFeatureSet()
		// Open the mesh connection
		mesh := m.Mesh(meshID)
		if mesh == nil {
			// This should never happen
			return handleErr(fmt.Errorf("mesh %q not found", meshID))
		}
		err := mesh.Open(ctx, features)
		if err != nil {
			return handleErr(fmt.Errorf("failed to open mesh %q: %w", meshID, err))
		}
		cleanFuncs = append(cleanFuncs, func() {
			err := mesh.Close()
			if err != nil {
				m.log.Error("failed to close mesh", slog.String("mesh-id", meshID), slog.String("error", err.Error()))
			}
		})
		// Create the services for this mesh
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
	return nil
}

// Stop stops the bridge. This closes all meshes and services.
func (m *meshBridge) Stop(ctx context.Context) error {
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
