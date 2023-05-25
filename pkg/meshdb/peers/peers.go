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

// Package peers contains an interface for managing nodes in the mesh.
package peers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"gitlab.com/webmesh/node/pkg/models/raftdb"
	"gitlab.com/webmesh/node/pkg/store"
)

// ErrNodeNotFound is returned when a node is not found.
var ErrNodeNotFound = errors.New("node not found")

// Peers is the peers interface.
type Peers interface {
	// Create creates a new node.
	Create(ctx context.Context, opts *CreateOptions) (*Node, error)
	// Get gets a node by ID.
	Get(ctx context.Context, id string) (*Node, error)
	// Update updates a node.
	Update(ctx context.Context, node *Node) (*Node, error)
	// Delete deletes a node.
	Delete(ctx context.Context, id string) error
	// List lists all nodes.
	List(ctx context.Context) ([]Node, error)
	// ListPeers lists all peers for a node.
	ListPeers(ctx context.Context, nodeID string) ([]Node, error)
}

// Node represents a node. Not all fields are populated in all contexts.
// A fully populated node is returned by Get and List.
type Node struct {
	// ID is the node's ID.
	ID string
	// PublicKey is the node's public key.
	PublicKey wgtypes.Key
	// Endpoint is the node's public endpoint.
	Endpoint netip.Addr
	// PrivateIPv4 is the node's private IPv4 address.
	PrivateIPv4 netip.Prefix
	// NetworkIPv6 is the node's IPv6 network.
	NetworkIPv6 netip.Prefix
	// GRPCPort is the node's GRPC port.
	GRPCPort int
	// RaftPort is the node's Raft port.
	RaftPort int
	// WireguardPort is the node's Wireguard port.
	WireguardPort int
	// CreatedAt is the time the node was created.
	CreatedAt time.Time
	// UpdatedAt is the time the node was last updated.
	UpdatedAt time.Time
}

// CreateOptions are options for creating a node.
type CreateOptions struct {
	// ID is the node's ID.
	ID string
	// PublicKey is the node's public key.
	PublicKey wgtypes.Key
	// Endpoint is the public endpoint of the node.
	Endpoint netip.Addr
	// NetworkIPv6 is true if the node's network is IPv6.
	NetworkIPv6 netip.Prefix
	// GRPCPort is the node's GRPC port.
	GRPCPort int
	// RaftPort is the node's Raft port.
	RaftPort int
	// WireguardPort is the node's Wireguard port.
	WireguardPort int
}

// New returns a new Peers interface.
func New(store store.Store) Peers {
	return &peers{store}
}

type peers struct {
	store store.Store
}

// Delete deletes a node.
func (p *peers) Delete(ctx context.Context, id string) error {
	q := raftdb.New(p.store.DB())
	if err := q.DeleteNode(ctx, id); err != nil {
		return fmt.Errorf("delete node: %w", err)
	}
	return nil
}

// Create creates a new node.
func (p *peers) Create(ctx context.Context, opts *CreateOptions) (*Node, error) {
	q := raftdb.New(p.store.DB())
	params := raftdb.CreateNodeParams{
		ID: opts.ID,
		PublicKey: sql.NullString{
			String: opts.PublicKey.String(),
			Valid:  true,
		},
		GrpcPort:      int64(opts.GRPCPort),
		RaftPort:      int64(opts.RaftPort),
		WireguardPort: int64(opts.WireguardPort),
		CreatedAt:     time.Now().UTC(),
		UpdatedAt:     time.Now().UTC(),
	}
	if opts.NetworkIPv6.IsValid() {
		params.NetworkIpv6 = sql.NullString{
			String: opts.NetworkIPv6.String(),
			Valid:  true,
		}
	}
	if opts.Endpoint.IsValid() {
		params.Endpoint = sql.NullString{
			String: opts.Endpoint.String(),
			Valid:  true,
		}
	}
	node, err := q.CreateNode(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("create node: %w", err)
	}
	out, err := nodeModelToNode(&node)
	if err != nil {
		return nil, fmt.Errorf("convert node model to node: %w", err)
	}
	return out, nil
}

// Get gets a node by public key.
func (p *peers) Get(ctx context.Context, id string) (*Node, error) {
	q := raftdb.New(p.store.ReadDB())
	node, err := q.GetNode(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNodeNotFound
		}
		return nil, err
	}
	var key wgtypes.Key
	if node.PublicKey.Valid {
		key, err = wgtypes.ParseKey(node.PublicKey.String)
		if err != nil {
			return nil, fmt.Errorf("parse node public key: %w", err)
		}
	}
	var endpoint netip.Addr
	if node.Endpoint.Valid {
		endpoint, err = netip.ParseAddr(node.Endpoint.String)
		if err != nil {
			return nil, fmt.Errorf("parse node endpoint: %w", err)
		}
	}
	var privateIPv4, privateIPv6 netip.Prefix
	if node.PrivateAddressV4 != "" {
		privateIPv4, err = netip.ParsePrefix(node.PrivateAddressV4)
		if err != nil {
			return nil, fmt.Errorf("parse node private IPv4: %w", err)
		}
	}
	if node.NetworkIpv6.Valid {
		privateIPv6, err = netip.ParsePrefix(node.NetworkIpv6.String)
		if err != nil {
			return nil, fmt.Errorf("parse node private IPv6: %w", err)
		}
	}
	return &Node{
		ID:            node.ID,
		PublicKey:     key,
		Endpoint:      endpoint,
		PrivateIPv4:   privateIPv4,
		NetworkIPv6:   privateIPv6,
		GRPCPort:      int(node.GrpcPort),
		RaftPort:      int(node.RaftPort),
		WireguardPort: int(node.WireguardPort),
		UpdatedAt:     node.UpdatedAt,
		CreatedAt:     node.CreatedAt,
	}, nil
}

// Update updates a node.
func (p *peers) Update(ctx context.Context, node *Node) (*Node, error) {
	q := raftdb.New(p.store.DB())
	params := raftdb.UpdateNodeParams{
		ID:            node.ID,
		GrpcPort:      int64(node.GRPCPort),
		RaftPort:      int64(node.RaftPort),
		WireguardPort: int64(node.WireguardPort),
		PublicKey: sql.NullString{
			String: node.PublicKey.String(),
			Valid:  true,
		},
		UpdatedAt: time.Now().UTC(),
	}
	if node.Endpoint.IsValid() {
		params.Endpoint = sql.NullString{
			String: node.Endpoint.String(),
			Valid:  true,
		}
	}
	if node.NetworkIPv6.IsValid() {
		params.NetworkIpv6 = sql.NullString{
			String: node.NetworkIPv6.String(),
			Valid:  true,
		}
	}
	updated, err := q.UpdateNode(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("update node: %w", err)
	}
	out, err := nodeModelToNode(&updated)
	if err != nil {
		return nil, fmt.Errorf("convert node model to node: %w", err)
	}
	return out, nil
}

// List lists all nodes.
func (p *peers) List(ctx context.Context) ([]Node, error) {
	q := raftdb.New(p.store.ReadDB())
	nodes, err := q.ListNodes(ctx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return []Node{}, nil
		}
		return nil, err
	}
	out := make([]Node, len(nodes))
	for i, node := range nodes {
		var key wgtypes.Key
		if node.PublicKey.Valid {
			key, err = wgtypes.ParseKey(node.PublicKey.String)
			if err != nil {
				return nil, fmt.Errorf("parse node public key: %w", err)
			}
		}
		var endpoint netip.Addr
		if node.Endpoint.Valid {
			endpoint, err = netip.ParseAddr(node.Endpoint.String)
			if err != nil {
				return nil, fmt.Errorf("parse node endpoint: %w", err)
			}
		}
		var networkv4, networkv6 netip.Prefix
		if node.PrivateAddressV4 != "" {
			networkv4, err = netip.ParsePrefix(node.PrivateAddressV4)
			if err != nil {
				return nil, fmt.Errorf("parse node network IPv4: %w", err)
			}
		}
		if node.NetworkIpv6.Valid {
			networkv6, err = netip.ParsePrefix(node.NetworkIpv6.String)
			if err != nil {
				return nil, fmt.Errorf("parse node network IPv6: %w", err)
			}
		}
		out[i] = Node{
			ID:            node.ID,
			PublicKey:     key,
			Endpoint:      endpoint,
			PrivateIPv4:   networkv4,
			NetworkIPv6:   networkv6,
			GRPCPort:      int(node.GrpcPort),
			RaftPort:      int(node.RaftPort),
			WireguardPort: int(node.WireguardPort),
			UpdatedAt:     node.UpdatedAt,
			CreatedAt:     node.CreatedAt,
		}
	}
	return out, nil
}

// ListPeers lists all peers for a node.
func (p *peers) ListPeers(ctx context.Context, nodeID string) ([]Node, error) {
	q := raftdb.New(p.store.ReadDB())
	nodePeers, err := q.ListNodePeers(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	peers := make([]Node, len(nodePeers))
	for i, peer := range nodePeers {
		var key wgtypes.Key
		if peer.PublicKey.Valid {
			key, err = wgtypes.ParseKey(peer.PublicKey.String)
			if err != nil {
				return nil, fmt.Errorf("parse node public key: %w", err)
			}
		}
		var endpoint netip.Addr
		if peer.Endpoint.Valid {
			endpoint, err = netip.ParseAddr(peer.Endpoint.String)
			if err != nil {
				return nil, fmt.Errorf("parse node endpoint: %w", err)
			}
		}
		var networkv4, networkv6 netip.Prefix
		if peer.PrivateAddressV4 != "" {
			networkv4, err = netip.ParsePrefix(peer.PrivateAddressV4)
			if err != nil {
				return nil, fmt.Errorf("parse node network IPv4: %w", err)
			}
		}
		if peer.NetworkIpv6.Valid {
			networkv6, err = netip.ParsePrefix(peer.NetworkIpv6.String)
			if err != nil {
				return nil, fmt.Errorf("parse node network IPv6: %w", err)
			}
		}
		peers[i] = Node{
			ID:            peer.ID,
			PublicKey:     key,
			Endpoint:      endpoint,
			PrivateIPv4:   networkv4,
			NetworkIPv6:   networkv6,
			GRPCPort:      int(peer.GrpcPort),
			RaftPort:      int(peer.RaftPort),
			WireguardPort: int(peer.WireguardPort),
			UpdatedAt:     peer.UpdatedAt,
			CreatedAt:     peer.CreatedAt,
		}
	}
	return peers, nil
}

func nodeModelToNode(node *raftdb.Node) (*Node, error) {
	var err error
	var key wgtypes.Key
	var endpoint netip.Addr
	if node.PublicKey.Valid {
		key, err = wgtypes.ParseKey(node.PublicKey.String)
		if err != nil {
			return nil, fmt.Errorf("parse node public key: %w", err)
		}
	}
	if node.Endpoint.Valid {
		endpoint, err = netip.ParseAddr(node.Endpoint.String)
		if err != nil {
			return nil, fmt.Errorf("parse endpoint: %w", err)
		}
	}
	var networkV6 netip.Prefix
	if node.NetworkIpv6.Valid {
		networkV6, err = netip.ParsePrefix(node.NetworkIpv6.String)
		if err != nil {
			return nil, fmt.Errorf("parse network IPv6: %w", err)
		}
	}
	return &Node{
		ID:            node.ID,
		PublicKey:     key,
		Endpoint:      endpoint,
		NetworkIPv6:   networkV6,
		GRPCPort:      int(node.GrpcPort),
		RaftPort:      int(node.RaftPort),
		WireguardPort: int(node.WireguardPort),
		CreatedAt:     node.CreatedAt,
	}, nil
}
