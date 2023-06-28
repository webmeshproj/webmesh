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

// Package state provides an interface for querying mesh state.
package state

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"

	v1 "github.com/webmeshproj/api/v1"
	"golang.org/x/exp/slog"
	"google.golang.org/grpc"

	"github.com/webmeshproj/node/pkg/meshdb"
	"github.com/webmeshproj/node/pkg/meshdb/models"
)

// State is the interface for querying mesh state.
type State interface {
	// GetULAPrefix returns the ULA prefix.
	GetULAPrefix(ctx context.Context) (netip.Prefix, error)
	// GetIPv4Prefix returns the IPv4 prefix.
	GetIPv4Prefix(ctx context.Context) (netip.Prefix, error)
	// GetNodePrivateRPCAddress returns the private gRPC address for a node.
	GetNodePrivateRPCAddress(ctx context.Context, nodeID string) (netip.AddrPort, error)
	// ListPublicRPCAddresses returns all public gRPC addresses in the mesh.
	// The map key is the node ID.
	ListPublicRPCAddresses(ctx context.Context) (map[string]netip.AddrPort, error)
	// ListPeerPublicRPCAddresses returns all public gRPC addresses in the mesh excluding a node.
	// The map key is the node ID.
	ListPeerPublicRPCAddresses(ctx context.Context, nodeID string) (map[string]netip.AddrPort, error)
	// ListPeerPrivateRPCAddresses returns all private gRPC addresses in the mesh excluding a node.
	// The map key is the node ID.
	ListPeerPrivateRPCAddresses(ctx context.Context, nodeID string) (map[string]netip.AddrPort, error)
	// ListPublicPeersWithFeature returns all public peers of the given node with the given feature.
	// TODO: Creds are needed because this method calls the peers to get their feature set.
	// This should be replaced with tracking the features in the meshdb.
	ListPublicPeersWithFeature(ctx context.Context, creds []grpc.DialOption, nodeID string, feature v1.Feature) (map[string]netip.AddrPort, error)
}

// ErrNodeNotFound is returned when a node is not found.
var ErrNodeNotFound = sql.ErrNoRows

type state struct {
	q models.Querier
}

// New returns a new State.
func New(rdb meshdb.DBTX) State {
	return &state{q: models.New(rdb)}
}

func (s *state) GetULAPrefix(ctx context.Context) (netip.Prefix, error) {
	prefix, err := s.q.GetULAPrefix(ctx)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.ParsePrefix(prefix)
}

func (s *state) GetIPv4Prefix(ctx context.Context) (netip.Prefix, error) {
	prefix, err := s.q.GetIPv4Prefix(ctx)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.ParsePrefix(prefix)
}

func (s *state) GetNodePrivateRPCAddress(ctx context.Context, nodeID string) (netip.AddrPort, error) {
	addr, err := s.q.GetNodePrivateRPCAddress(ctx, nodeID)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.ParseAddrPort(addr.(string))
}

func (s *state) ListPublicRPCAddresses(ctx context.Context) (map[string]netip.AddrPort, error) {
	addrs, err := s.q.ListPublicRPCAddresses(ctx)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, nil
	}
	out := make(map[string]netip.AddrPort, len(addrs))
	for _, addr := range addrs {
		a, err := netip.ParseAddrPort(addr.Address.(string))
		if err != nil {
			return nil, err
		}
		out[addr.NodeID] = a
	}
	return out, nil
}

func (s *state) ListPeerPublicRPCAddresses(ctx context.Context, nodeID string) (map[string]netip.AddrPort, error) {
	addrs, err := s.q.ListPeerPublicRPCAddresses(ctx, nodeID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, nil
	}
	out := make(map[string]netip.AddrPort, len(addrs))
	for _, addr := range addrs {
		a, err := netip.ParseAddrPort(addr.Address.(string))
		if err != nil {
			return nil, err
		}
		out[addr.NodeID] = a
	}
	return out, nil
}

func (s *state) ListPeerPrivateRPCAddresses(ctx context.Context, nodeID string) (map[string]netip.AddrPort, error) {
	addrs, err := s.q.ListPeerPrivateRPCAddresses(ctx, nodeID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, nil
	}
	out := make(map[string]netip.AddrPort, len(addrs))
	for _, addr := range addrs {
		a, err := netip.ParseAddrPort(addr.Address.(string))
		if err != nil {
			return nil, err
		}
		out[addr.NodeID] = a
	}
	return out, nil
}

func (s *state) ListPublicPeersWithFeature(ctx context.Context, creds []grpc.DialOption, nodeID string, feature v1.Feature) (map[string]netip.AddrPort, error) {
	publicAddrs, err := s.ListPeerPublicRPCAddresses(ctx, nodeID)
	if err != nil {
		return nil, fmt.Errorf("list public addresses: %w", err)
	}
	if len(publicAddrs) == 0 {
		return nil, nil
	}
	privateAddrs, err := s.ListPeerPrivateRPCAddresses(ctx, nodeID)
	if err != nil {
		return nil, fmt.Errorf("list private addresses: %w", err)
	}
	out := make(map[string]netip.AddrPort)
	for node, publicAddr := range publicAddrs {
		privAddr, ok := privateAddrs[node]
		if !ok {
			continue
		}
		slog.Default().Debug("checking node for feature",
			slog.String("feature", feature.String()),
			slog.String("node", node),
			slog.String("addr", privAddr.String()),
		)
		conn, err := grpc.DialContext(ctx, privAddr.String(), creds...)
		if err != nil {
			slog.Default().Debug("could not connect to node",
				slog.String("node", node),
				slog.String("addr", privAddr.String()),
				slog.String("error", err.Error()))
			continue
		}
		defer conn.Close()
		cl := v1.NewNodeClient(conn)
		// TODO: Need an RPC for just features
		status, err := cl.GetStatus(ctx, &v1.GetStatusRequest{})
		if err != nil {
			slog.Default().Debug("could not get status from node",
				slog.String("node", node),
				slog.String("addr", privAddr.String()),
				slog.String("error", err.Error()))
			continue
		}
	Feats:
		for _, f := range status.GetFeatures() {
			if f == feature {
				out[node] = publicAddr
				break Feats
			}
		}
	}
	return out, nil
}
