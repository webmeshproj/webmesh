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

package types

import (
	"fmt"
	"io"
	"reflect"

	"github.com/dominikbraun/graph"
	"github.com/dominikbraun/graph/draw"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/storage/errors"
)

// PeerGraph is the graph.Graph implementation for the mesh network.
type PeerGraph graph.Graph[NodeID, MeshNode]

// PeerGraphStore is the graph.Store implementation for the mesh network.
type PeerGraphStore graph.Store[NodeID, MeshNode]

// DrawPeerGraph draws a PeerGraph to the given writer in DOT format.
func DrawPeerGraph(ctx context.Context, g PeerGraph, w io.Writer) error {
	err := draw.DOT(g, w)
	if err != nil {
		return fmt.Errorf("draw graph: %w", err)
	}
	return nil
}

// AdjacencyMap is a map of node names to a map of node names to edges.
type AdjacencyMap map[NodeID]EdgeMap

// NewAdjacencyMap returns a new adjacency map for the graph.
func NewAdjacencyMap(g PeerGraph) (AdjacencyMap, error) {
	m, err := g.AdjacencyMap()
	if err != nil {
		return nil, fmt.Errorf("get adjacency map: %w", err)
	}
	out := make(AdjacencyMap, len(m))
	for source, targets := range m {
		out[source] = make(map[NodeID]Edge, len(targets))
		for target, edge := range targets {
			out[source][target] = Edge(edge)
		}
	}
	return out, nil
}

// DeepEqual returns true if the given AdjacencyMap is equal to this AdjacencyMap.
func (a AdjacencyMap) DeepEqual(b AdjacencyMap) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if !v.DeepEqual(b[k]) {
			return false
		}
	}
	return true
}

// EdgeMap is a map of node names to edges.
type EdgeMap map[NodeID]Edge

// DeepEqual returns true if the given EdgeMap is equal to this EdgeMap.
func (e EdgeMap) DeepEqual(other EdgeMap) bool {
	if len(e) != len(other) {
		return false
	}
	for k, v := range e {
		if !v.DeepEqual(other[k]) {
			return false
		}
	}
	return true
}

// Edge is the graph.Edge implementation for the mesh network.
type Edge graph.Edge[NodeID]

// ToMeshEdge converts an Edge to a MeshEdge.
func (e Edge) ToMeshEdge(source, target NodeID) MeshEdge {
	return MeshEdge{
		MeshEdge: &v1.MeshEdge{
			Source:     source.String(),
			Target:     target.String(),
			Weight:     int32(e.Properties.Weight),
			Attributes: e.Properties.Attributes,
		},
	}
}

// DeepEqual returns true if the given Edge is equal to this Edge.
func (e Edge) DeepEqual(other Edge) bool {
	return e.Source == other.Source &&
		e.Target == other.Target &&
		e.Properties.Weight == other.Properties.Weight &&
		reflect.DeepEqual(e.Properties.Attributes, other.Properties.Attributes)
}

// MeshEdge wraps a mesh edge.
type MeshEdge struct {
	*v1.MeshEdge `json:",inline"`
}

// DeepCopy returns a deep copy of the edge.
func (e MeshEdge) DeepCopy() MeshEdge {
	return MeshEdge{MeshEdge: e.MeshEdge.DeepCopy()}
}

// DeepCopyInto copies the edge into the given edge.
func (e MeshEdge) DeepCopyInto(edge *MeshEdge) {
	*edge = e.DeepCopy()
}

// SourceID returns the source node's ID.
func (e MeshEdge) SourceID() NodeID {
	return NodeID(e.GetSource())
}

// TargetID returns the target node's ID.
func (e MeshEdge) TargetID() NodeID {
	return NodeID(e.GetTarget())
}

// EdgeProperties returns the edge's properties.
func (e MeshEdge) EdgeProperties() graph.EdgeProperties {
	return graph.EdgeProperties{
		Weight:     int(e.Weight),
		Attributes: e.Attributes,
	}
}

// AsGraphEdge converts a MeshEdge to a graph.Edge.
func (e MeshEdge) AsGraphEdge() graph.Edge[NodeID] {
	return graph.Edge[NodeID](e.ToEdge())
}

// ToEdge converts a MeshEdge to an Edge.
func (e MeshEdge) ToEdge() Edge {
	if len(e.Attributes) == 0 {
		e.Attributes = make(map[string]string)
	}
	return Edge{
		Source:     e.SourceID(),
		Target:     e.TargetID(),
		Properties: e.EdgeProperties(),
	}
}

// MarshalProtoJSON marshals a MeshEdge to JSON.
func (e MeshEdge) MarshalProtoJSON() ([]byte, error) {
	return protojson.Marshal(e.MeshEdge)
}

// UnmarshalProtoJSON unmarshals a MeshEdge from JSON.
func (e *MeshEdge) UnmarshalProtoJSON(data []byte) error {
	var edge v1.MeshEdge
	if err := protojson.Unmarshal(data, &edge); err != nil {
		return err
	}
	e.MeshEdge = &edge
	return nil
}

// PutInto puts the MeshEdge into the given graph.
func (e MeshEdge) PutInto(ctx context.Context, g PeerGraph) error {
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

// EdgeAttrsForConnectProto returns the edge attributes for the given protocol.
func EdgeAttrsForConnectProto(proto v1.ConnectProtocol) map[string]string {
	attrs := map[string]string{}
	switch proto {
	case v1.ConnectProtocol_CONNECT_ICE:
		attrs[v1.EdgeAttribute_EDGE_ATTRIBUTE_ICE.String()] = "true"
	case v1.ConnectProtocol_CONNECT_LIBP2P:
		attrs[v1.EdgeAttribute_EDGE_ATTRIBUTE_LIBP2P.String()] = "true"
	default:
		attrs[v1.EdgeAttribute_EDGE_ATTRIBUTE_NATIVE.String()] = "true"
	}
	return attrs
}

// ConnectProtoFromEdgeAttrs returns the protocol for the given edge attributes.
func ConnectProtoFromEdgeAttrs(attrs map[string]string) v1.ConnectProtocol {
	if attrs == nil {
		return v1.ConnectProtocol_CONNECT_NATIVE
	}
	if _, ok := attrs[v1.EdgeAttribute_EDGE_ATTRIBUTE_ICE.String()]; ok {
		return v1.ConnectProtocol_CONNECT_ICE
	}
	if _, ok := attrs[v1.EdgeAttribute_EDGE_ATTRIBUTE_LIBP2P.String()]; ok {
		return v1.ConnectProtocol_CONNECT_LIBP2P
	}
	return v1.ConnectProtocol_CONNECT_NATIVE
}
