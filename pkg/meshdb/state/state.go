/*
Copyright 2023.

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
	"net/netip"

	"gitlab.com/webmesh/node/pkg/db/raftdb"
	"gitlab.com/webmesh/node/pkg/store"
)

// State is the interface for querying mesh state.
type State interface {
	// GetULAPrefix returns the ULA prefix.
	GetULAPrefix(ctx context.Context) (netip.Prefix, error)
	// GetIPv4Prefix returns the IPv4 prefix.
	GetIPv4Prefix(ctx context.Context) (netip.Prefix, error)
	// GetNodePrivateRPCAddress returns the private gRPC address for a node.
	GetNodePrivateRPCAddress(ctx context.Context, nodeID string) (netip.AddrPort, error)
}

type state struct {
	q raftdb.Querier
}

// New returns a new State.
func New(st store.Store) State {
	return &state{q: raftdb.New(st.ReadDB())}
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
