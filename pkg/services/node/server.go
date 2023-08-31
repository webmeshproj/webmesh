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

// Package node contains the webmesh node service.
package node

import (
	"log/slog"
	"net/netip"
	"time"

	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/net/transport"
	"github.com/webmeshproj/webmesh/pkg/net/wireguard"
	"github.com/webmeshproj/webmesh/pkg/plugins"
	"github.com/webmeshproj/webmesh/pkg/raft"
)

// Server is the webmesh node service.
type Server struct {
	v1.UnimplementedNodeServer
	Options
	startedAt time.Time
	log       *slog.Logger
}

// Options are options for the Node service.
type Options struct {
	Raft       raft.Raft
	WireGuard  wireguard.Interface
	NodeDialer transport.NodeDialer
	Plugins    plugins.Manager
	Features   []*v1.FeaturePort
	NetworkV4  netip.Prefix
	NetworkV6  netip.Prefix
}

// NewServer returns a new Server. Features are used for returning what features are enabled.
// It is the callers responsibility to ensure those servers are registered on the node.
// Insecure is used to disable authorization.
func NewServer(ctx context.Context, opts Options) *Server {
	return &Server{
		Options:   opts,
		startedAt: time.Now(),
		log:       context.LoggerFrom(ctx).With("component", "node-server"),
	}
}
