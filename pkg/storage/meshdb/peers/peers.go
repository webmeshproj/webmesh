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

// Package peers contains an interface for managing nodes in the mesh.
package peers

import (
	"bytes"
	"fmt"
	"time"

	"github.com/dominikbraun/graph"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/errors"
	"github.com/webmeshproj/webmesh/pkg/storage/meshdb/graphstore"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

type Peers = storage.Peers

// New returns a new Peers interface.
func New(db storage.MeshStorage) Peers {
	return &peerDB{
		db:    db,
		graph: types.NewGraphWithStore(graphstore.NewStore(db)),
	}
}

type peerDB struct {
	db    storage.MeshStorage
	graph types.PeerGraph
}

func (p *peerDB) Put(ctx context.Context, node types.MeshNode) error {
	// Dedup the wireguard endpoints.
	seen := make(map[string]struct{})
	var wgendpoints []string
	for _, endpoint := range node.GetWireguardEndpoints() {
		if _, ok := seen[endpoint]; ok {
			continue
		}
		seen[endpoint] = struct{}{}
		wgendpoints = append(wgendpoints, endpoint)
	}
	node.WireguardEndpoints = wgendpoints
	// TODO: Track this separately or consider changing to UpdatedAt.
	node.JoinedAt = timestamppb.New(time.Now().UTC())
	err := p.graph.AddVertex(node)
	if err != nil {
		return fmt.Errorf("put node: %w", err)
	}
	return nil
}

func (p *peerDB) Get(ctx context.Context, id types.NodeID) (types.MeshNode, error) {
	node, err := p.graph.Vertex(id)
	if err != nil {
		if errors.Is(err, graph.ErrVertexNotFound) {
			return types.MeshNode{}, errors.ErrNodeNotFound
		}
		return types.MeshNode{}, fmt.Errorf("get node: %w", err)
	}
	return node, nil
}

// GetByPubKey gets a node by their public key.
func (p *peerDB) GetByPubKey(ctx context.Context, key crypto.PublicKey) (types.MeshNode, error) {
	nodes, err := p.List(ctx)
	if err != nil {
		return types.MeshNode{}, fmt.Errorf("list nodes: %w", err)
	}
	for _, node := range nodes {
		if node.GetPublicKey() != "" {
			key, err := crypto.DecodePublicKey(node.GetPublicKey())
			if err != nil {
				return types.MeshNode{}, fmt.Errorf("parse host public key: %w", err)
			}
			if key.Equals(key) {
				return node, nil
			}
		}
	}
	return types.MeshNode{}, errors.ErrNodeNotFound
}

func (p *peerDB) Delete(ctx context.Context, id types.NodeID) error {
	edges, err := p.graph.Edges()
	if err != nil {
		return fmt.Errorf("get edges: %w", err)
	}
	for _, edge := range edges {
		if edge.Source.String() == id.String() || edge.Target.String() == id.String() {
			err = p.graph.RemoveEdge(edge.Source, edge.Target)
			if err != nil {
				return fmt.Errorf("remove edge: %w", err)
			}
		}
	}
	err = p.graph.RemoveVertex(types.NodeID(id))
	if err != nil {
		if errors.Is(err, graph.ErrVertexNotFound) {
			// We don't return this error in the graph store
			// implementation, so we don't return it here either.
			return nil
		}
		return fmt.Errorf("remove vertex: %w", err)
	}
	return nil
}

func (p *peerDB) List(ctx context.Context, filters ...storage.PeerFilter) ([]types.MeshNode, error) {
	out := make([]types.MeshNode, 0)
	err := p.db.IterPrefix(ctx, storage.NodesPrefix, func(key, value []byte) error {
		if bytes.Equal(key, storage.NodesPrefix) {
			return nil
		}
		var node types.MeshNode
		err := node.UnmarshalJSON(value)
		if err != nil {
			return fmt.Errorf("unmarshal node: %w", err)
		}
		out = append(out, node)
		return nil
	})
	return storage.PeerFilters(filters).Filter(out), err
}

func (p *peerDB) ListIDs(ctx context.Context) ([]types.NodeID, error) {
	keys, err := p.db.ListKeys(ctx, storage.NodesPrefix)
	if err != nil {
		return nil, fmt.Errorf("list keys: %w", err)
	}
	ids := make([]types.NodeID, 0)
	for _, key := range keys {
		if bytes.Equal(key, storage.NodesPrefix) {
			continue
		}
		ids = append(ids, types.NodeID(storage.NodesPrefix.TrimFrom(key)))
	}
	return ids, nil
}

func (p *peerDB) Subscribe(ctx context.Context, fn storage.PeerSubscribeFunc) (context.CancelFunc, error) {
	log := context.LoggerFrom(ctx)
	return p.db.Subscribe(ctx, []byte(""), func(key, value []byte) {
		var nodes []types.MeshNode
		switch {
		case bytes.HasPrefix(key, storage.EdgesPrefix):
			if bytes.Equal(key, storage.EdgesPrefix) {
				return
			}
			var edge types.MeshEdge
			err := edge.UnmarshalJSON(value)
			if err != nil {
				log.Error("Failed to unmarshal edge", "error", err.Error())
				return
			}
			source, err := p.graph.Vertex(edge.SourceID())
			if err != nil {
				log.Error("Failed to get source node", "error", err.Error())
			} else {
				nodes = append(nodes, source)
			}
			target, err := p.graph.Vertex(edge.TargetID())
			if err != nil {
				log.Error("Failed to get target node", "error", err.Error())
			} else {
				nodes = append(nodes, target)
			}
		case bytes.HasPrefix(key, storage.NodesPrefix):
			if bytes.Equal(key, storage.NodesPrefix) {
				return
			}
			var node types.MeshNode
			err := node.UnmarshalJSON(value)
			if err != nil {
				log.Error("Failed to unmarshal node", "error", err.Error())
				return
			}
			nodes = append(nodes, node)
		}
		if len(nodes) > 0 {
			fn(nodes)
		}
	})
}

func (p *peerDB) PutEdge(ctx context.Context, edge types.MeshEdge) error {
	if edge.Source == edge.Target {
		return nil
	}
	return edge.PutInto(ctx, p.graph)
}

func (p *peerDB) GetEdge(ctx context.Context, source, target types.NodeID) (types.MeshEdge, error) {
	edge, err := p.graph.Edge(source, target)
	if err != nil {
		if errors.Is(err, graph.ErrEdgeNotFound) {
			return types.MeshEdge{}, errors.ErrEdgeNotFound
		}
		return types.MeshEdge{}, fmt.Errorf("get edge: %w", err)
	}
	return types.MeshEdge{MeshEdge: &v1.MeshEdge{
		Source:     edge.Source.GetId(),
		Target:     edge.Target.GetId(),
		Weight:     int32(edge.Properties.Weight),
		Attributes: edge.Properties.Attributes,
	}}, nil
}

func (p *peerDB) RemoveEdge(ctx context.Context, from, to types.NodeID) error {
	err := p.graph.RemoveEdge(from, to)
	if err != nil {
		if err == graph.ErrEdgeNotFound {
			return nil
		}
		return fmt.Errorf("remove edge: %w", err)
	}
	return nil
}
