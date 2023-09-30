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
	"io"
	"reflect"
	"time"

	"github.com/dominikbraun/graph"
	"github.com/dominikbraun/graph/draw"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/errors"
	peergraph "github.com/webmeshproj/webmesh/pkg/storage/meshdb/graph"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

type Peers = storage.Peers

// New returns a new Peers interface.
func New(db storage.MeshStorage) Peers {
	return &peerDB{
		db:    db,
		graph: types.NewGraphWithStore(peergraph.NewGraphStore(db)),
	}
}

type peerDB struct {
	db    storage.MeshStorage
	graph types.PeerGraph
}

func (p *peerDB) Graph() types.PeerGraph { return p.graph }

func (p *peerDB) Put(ctx context.Context, node *v1.MeshNode) error {
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
	err := p.graph.AddVertex(types.MeshNode{MeshNode: node})
	if err != nil {
		return fmt.Errorf("put node: %w", err)
	}
	return nil
}

func (p *peerDB) Get(ctx context.Context, id string) (types.MeshNode, error) {
	node, err := p.graph.Vertex(types.NodeID(id))
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

func (p *peerDB) Delete(ctx context.Context, id string) error {
	edges, err := p.graph.Edges()
	if err != nil {
		return fmt.Errorf("get edges: %w", err)
	}
	for _, edge := range edges {
		if edge.Source.String() == id || edge.Target.String() == id {
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

func (p *peerDB) List(ctx context.Context) ([]types.MeshNode, error) {
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
	return out, err
}

func (p *peerDB) ListIDs(ctx context.Context) ([]string, error) {
	keys, err := p.db.ListKeys(ctx, storage.NodesPrefix)
	if err != nil {
		return nil, fmt.Errorf("list keys: %w", err)
	}
	ids := make([]string, 0)
	for _, key := range keys {
		if bytes.Equal(key, storage.NodesPrefix) {
			continue
		}
		ids = append(ids, string(storage.NodesPrefix.TrimFrom(key)))
	}
	return ids, nil
}

func (p *peerDB) ListPublicNodes(ctx context.Context) ([]types.MeshNode, error) {
	nodes, err := p.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	out := make([]types.MeshNode, 0)
	for _, node := range nodes {
		n := node
		if n.PrimaryEndpoint != "" {
			out = append(out, n)
		}
	}
	return out, nil
}

func (p *peerDB) ListByZoneID(ctx context.Context, zoneID string) ([]types.MeshNode, error) {
	nodes, err := p.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	out := make([]types.MeshNode, 0)
	for _, node := range nodes {
		n := node
		if n.GetZoneAwarenessId() == zoneID {
			out = append(out, n)
		}
	}
	return out, nil
}

func (p *peerDB) ListByFeature(ctx context.Context, feature v1.Feature) ([]types.MeshNode, error) {
	nodes, err := p.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	out := make([]types.MeshNode, 0)
	for _, node := range nodes {
		n := node
		if n.HasFeature(feature) {
			out = append(out, n)
		}
	}
	return out, nil
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

func (p *peerDB) PutEdge(ctx context.Context, edge *v1.MeshEdge) error {
	if edge.Source == edge.Target {
		return nil
	}
	e := types.MeshEdge{MeshEdge: edge}
	return PutMeshEdgeInto(e, p.graph)
}

func (p *peerDB) RemoveEdge(ctx context.Context, from, to string) error {
	err := p.graph.RemoveEdge(types.NodeID(from), types.NodeID(to))
	if err != nil {
		if err == graph.ErrEdgeNotFound {
			return nil
		}
		return fmt.Errorf("remove edge: %w", err)
	}
	return nil
}

func (p *peerDB) DrawDOTGraph(ctx context.Context, w io.Writer) error {
	graph := graph.Graph[types.NodeID, types.MeshNode](p.graph)
	err := draw.DOT(graph, w)
	if err != nil {
		return fmt.Errorf("draw graph: %w", err)
	}
	return nil
}

// PutMeshEdgeInto puts the MeshEdge into the given graph.
func PutMeshEdgeInto(e types.MeshEdge, g types.PeerGraph) error {
	opts := []func(*graph.EdgeProperties){graph.EdgeWeight(int(e.Weight))}
	if len(e.Attributes) > 0 {
		for k, v := range e.Attributes {
			opts = append(opts, graph.EdgeAttribute(k, v))
		}
	}
	// Save the raft log some trouble by checking if the edge already exists.
	graphEdge, err := g.Edge(e.SourceID(), e.TargetID())
	if err == nil {
		// Check if the weight or attributes changed
		if !reflect.DeepEqual(graphEdge.Properties.Attributes, e.Attributes) {
			return g.UpdateEdge(e.SourceID(), e.TargetID(), opts...)
		}
		if graphEdge.Properties.Weight != int(e.Weight) {
			return g.UpdateEdge(e.SourceID(), e.TargetID(), opts...)
		}
		return nil
	}
	if !errors.IsEdgeNotFound(err) {
		return fmt.Errorf("get edge: %w", err)
	}
	err = g.AddEdge(e.SourceID(), e.TargetID(), opts...)
	if err != nil && !errors.Is(err, graph.ErrEdgeAlreadyExists) {
		return fmt.Errorf("add edge: %w", err)
	}
	return nil
}
