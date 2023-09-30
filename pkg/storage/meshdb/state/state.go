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
	"net/netip"

	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/meshdb/peers"
)

type State = storage.MeshState

// ErrNodeNotFound is returned when a node is not found.
var ErrNodeNotFound = sql.ErrNoRows

var (
	// MeshStatePrefix is the prefix for mesh state keys.
	MeshStatePrefix = []byte("/registry/meshstate")
	// IPv6PrefixKey is the key for the IPv6 prefix.
	IPv6PrefixKey = append(MeshStatePrefix, []byte("/ipv6prefix")...)
	// IPv4PrefixKey is the key for the IPv4 prefix.
	IPv4PrefixKey = append(MeshStatePrefix, []byte("/ipv4prefix")...)
	// MeshDomainKey is the key for the mesh domain.
	MeshDomainKey = append(MeshStatePrefix, []byte("/meshdomain")...)
)

type state struct {
	storage.MeshStorage
}

// New returns a new State.
func New(db storage.MeshStorage) State {
	return &state{db}
}

func (s *state) GetIPv6Prefix(ctx context.Context) (netip.Prefix, error) {
	prefix, err := s.GetValue(ctx, IPv6PrefixKey)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.ParsePrefix(string(prefix))
}

func (s *state) SetIPv6Prefix(ctx context.Context, prefix netip.Prefix) error {
	err := s.PutValue(ctx, IPv6PrefixKey, []byte(prefix.String()), 0)
	if err != nil {
		return err
	}
	return nil
}

func (s *state) GetIPv4Prefix(ctx context.Context) (netip.Prefix, error) {
	prefix, err := s.GetValue(ctx, IPv4PrefixKey)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.ParsePrefix(string(prefix))
}

func (s *state) SetIPv4Prefix(ctx context.Context, prefix netip.Prefix) error {
	err := s.PutValue(ctx, IPv4PrefixKey, []byte(prefix.String()), 0)
	if err != nil {
		return err
	}
	return nil
}

func (s *state) GetMeshDomain(ctx context.Context) (string, error) {
	resp, err := s.GetValue(ctx, MeshDomainKey)
	if err != nil {
		return "", err
	}
	return string(resp), nil
}

func (s *state) SetMeshDomain(ctx context.Context, domain string) error {
	err := s.PutValue(ctx, MeshDomainKey, []byte(domain), 0)
	if err != nil {
		return err
	}
	return nil
}

func (s *state) ListPublicRPCAddresses(ctx context.Context) (map[string]netip.AddrPort, error) {
	nodes, err := peers.New(s).List(ctx, storage.IsPublicFilter())
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, nil
	}
	out := make(map[string]netip.AddrPort)
	for _, node := range nodes {
		if addr := node.PublicRPCAddr(); addr.IsValid() {
			out[node.GetId()] = addr
		}
	}
	return out, nil
}

func (s *state) ListPeerPublicRPCAddresses(ctx context.Context, nodeID string) (map[string]netip.AddrPort, error) {
	nodes, err := s.ListPublicRPCAddresses(ctx)
	if err != nil {
		return nil, err
	}
	for node := range nodes {
		if node == nodeID {
			delete(nodes, node)
			break
		}
	}
	return nodes, nil
}

func (s *state) ListPeerPrivateRPCAddresses(ctx context.Context, nodeID string) (map[string]netip.AddrPort, error) {
	nodes, err := peers.New(s).List(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]netip.AddrPort)
	for _, node := range nodes {
		if node.GetId() == nodeID {
			continue
		}
		var addr netip.AddrPort
		if node.PrivateRPCAddrV4().IsValid() {
			addr = node.PrivateRPCAddrV4()
		} else {
			addr = node.PrivateRPCAddrV6()
		}
		out[node.GetId()] = addr
	}
	return out, nil
}
