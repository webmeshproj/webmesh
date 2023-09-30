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

// Package networking contains interfaces to the database models for Network ACLs and Routes.
package networking

import (
	"bytes"
	"fmt"
	"net/netip"

	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/errors"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

type Networking = storage.Networking

// New returns a new Networking interface.
func New(st storage.MeshStorage) Networking {
	return &networking{st}
}

type networking struct {
	storage.MeshStorage
}

// PutNetworkACL creates or updates a NetworkACL.
func (n *networking) PutNetworkACL(ctx context.Context, acl *v1.NetworkACL) error {
	err := types.ValidateACL(acl)
	if err != nil {
		return fmt.Errorf("%w: %w", errors.ErrInvalidACL, err)
	}
	key := storage.NetworkACLsPrefix.For([]byte(acl.GetName()))
	data, err := (types.NetworkACL{NetworkACL: acl}).MarshalJSON()
	if err != nil {
		return fmt.Errorf("marshal network acl: %w", err)
	}
	err = n.PutValue(ctx, key, data, 0)
	if err != nil {
		return fmt.Errorf("put network acl: %w", err)
	}
	return nil
}

// GetNetworkACL returns a NetworkACL by name.
func (n *networking) GetNetworkACL(ctx context.Context, name string) (types.NetworkACL, error) {
	key := storage.NetworkACLsPrefix.For([]byte(name))
	data, err := n.GetValue(ctx, key)
	if err != nil {
		if errors.IsKeyNotFound(err) {
			return types.NetworkACL{}, errors.ErrACLNotFound
		}
		return types.NetworkACL{}, fmt.Errorf("get network acl: %w", err)
	}
	var acl types.NetworkACL
	err = acl.UnmarshalJSON(data)
	if err != nil {
		return types.NetworkACL{}, fmt.Errorf("unmarshal network acl: %w", err)
	}
	return acl, nil
}

// DeleteNetworkACL deletes a NetworkACL by name.
func (n *networking) DeleteNetworkACL(ctx context.Context, name string) error {
	key := storage.NetworkACLsPrefix.For([]byte(name))
	err := n.Delete(ctx, key)
	if err != nil && !errors.IsKeyNotFound(err) {
		return fmt.Errorf("delete network acl: %w", err)
	}
	return nil
}

// ListNetworkACLs returns a list of NetworkACLs.
func (n *networking) ListNetworkACLs(ctx context.Context) (types.NetworkACLs, error) {
	out := make(types.NetworkACLs, 0)
	err := n.IterPrefix(ctx, storage.NetworkACLsPrefix, func(key, value []byte) error {
		if bytes.Equal(key, storage.NetworkACLsPrefix) {
			return nil
		}
		var acl types.NetworkACL
		err := acl.UnmarshalJSON(value)
		if err != nil {
			return fmt.Errorf("unmarshal network acl: %w", err)
		}
		out = append(out, acl)
		return nil
	})
	return out, err
}

// PutRoute creates or updates a Route.
func (n *networking) PutRoute(ctx context.Context, route *v1.Route) error {
	err := types.ValidateRoute(route)
	if err != nil {
		return fmt.Errorf("%w: %w", errors.ErrInvalidRoute, err)
	}
	key := storage.RoutesPrefix.For([]byte(route.GetName()))
	data, err := (types.Route{Route: route}).MarshalJSON()
	if err != nil {
		return fmt.Errorf("marshal route: %w", err)
	}
	err = n.PutValue(ctx, key, data, 0)
	if err != nil {
		return fmt.Errorf("put network route: %w", err)
	}
	return nil
}

// GetRoute returns a Route by name.
func (n *networking) GetRoute(ctx context.Context, name string) (types.Route, error) {
	key := storage.RoutesPrefix.For([]byte(name))
	data, err := n.GetValue(ctx, key)
	if err != nil {
		if errors.IsKeyNotFound(err) {
			return types.Route{}, errors.ErrRouteNotFound
		}
		return types.Route{}, fmt.Errorf("get network route: %w", err)
	}
	var rt types.Route
	err = rt.UnmarshalJSON(data)
	if err != nil {
		return types.Route{}, fmt.Errorf("unmarshal network route: %w", err)
	}
	return rt, nil
}

// GetRoutesByNode returns a list of Routes for a given Node.
func (n *networking) GetRoutesByNode(ctx context.Context, nodeID types.NodeID) (types.Routes, error) {
	routes, err := n.ListRoutes(ctx)
	if err != nil {
		return nil, fmt.Errorf("list network routes: %w", err)
	}
	out := make([]types.Route, 0)
	for _, route := range routes {
		r := route
		if r.GetNode() == nodeID.String() {
			out = append(out, r)
		}
	}
	return out, nil
}

// GetRoutesByCIDR returns a list of Routes for a given CIDR.
func (n *networking) GetRoutesByCIDR(ctx context.Context, cidr netip.Prefix) (types.Routes, error) {
	routes, err := n.ListRoutes(ctx)
	if err != nil {
		return nil, fmt.Errorf("list network routes: %w", err)
	}
	out := make([]types.Route, 0)
	for _, route := range routes {
		r := route
		for _, destination := range r.DestinationPrefixes() {
			if destination.Bits() != cidr.Bits() {
				continue
			}
			if destination.Addr().Compare(cidr.Addr()) != 0 {
				continue
			}
			out = append(out, r)
		}
	}
	return out, nil
}

// DeleteRoute deletes a Route by name.
func (n *networking) DeleteRoute(ctx context.Context, name string) error {
	key := storage.RoutesPrefix.For([]byte(name))
	err := n.Delete(ctx, key)
	if err != nil && !errors.IsKeyNotFound(err) {
		return fmt.Errorf("delete network route: %w", err)
	}
	return nil
}

// ListRoutes returns a list of Routes.
func (n *networking) ListRoutes(ctx context.Context) (types.Routes, error) {
	out := make([]types.Route, 0)
	err := n.IterPrefix(ctx, storage.RoutesPrefix, func(key, value []byte) error {
		if bytes.Equal(key, storage.RoutesPrefix) {
			return nil
		}
		var rt types.Route
		err := rt.UnmarshalJSON(value)
		if err != nil {
			return fmt.Errorf("unmarshal network route: %w", err)
		}
		out = append(out, rt)
		return nil
	})
	return out, err
}
