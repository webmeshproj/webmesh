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
	"net/netip"

	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

type State = storage.MeshState

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

func (s *state) SetMeshState(ctx context.Context, state types.NetworkState) error {
	if state.NetworkV4().IsValid() {
		err := s.SetIPv4Prefix(ctx, state.NetworkV4())
		if err != nil {
			return err
		}
	}
	if state.NetworkV6().IsValid() {
		err := s.SetIPv6Prefix(ctx, state.NetworkV6())
		if err != nil {
			return err
		}
	}
	err := s.SetMeshDomain(ctx, state.Domain())
	if err != nil {
		return err
	}
	return nil
}

func (s *state) GetMeshState(ctx context.Context) (types.NetworkState, error) {
	state := types.NetworkState{
		NetworkState: &v1.NetworkState{},
	}
	domain, err := s.GetMeshDomain(ctx)
	if err != nil {
		return state, err
	}
	state.NetworkState.Domain = domain
	networkV4, err := s.GetIPv4Prefix(ctx)
	if err != nil {
		return state, err
	}
	state.NetworkState.NetworkV4 = networkV4.String()
	networkv6, err := s.GetIPv6Prefix(ctx)
	if err != nil {
		return state, err
	}
	state.NetworkState.NetworkV6 = networkv6.String()
	return state, nil
}
