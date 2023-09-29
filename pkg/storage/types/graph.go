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
	"reflect"

	"github.com/dominikbraun/graph"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// PeerGraph is the graph.Graph implementation for the mesh network.
type PeerGraph graph.Graph[NodeID, MeshNode]

// PeerGraphStore is the graph.Store implementation for the mesh network.
type PeerGraphStore graph.Store[NodeID, MeshNode]

// AdjacencyMap is a map of node names to a map of node names to edges.
type AdjacencyMap map[NodeID]EdgeMap

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
type MeshEdge struct{ *v1.MeshEdge }

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

// MarshalJSON marshals a MeshEdge to JSON.
func (e MeshEdge) MarshalJSON() ([]byte, error) {
	return protojson.Marshal(e.MeshEdge)
}

// UnmarshalJSON unmarshals a MeshEdge from JSON.
func (e *MeshEdge) UnmarshalJSON(data []byte) error {
	var edge v1.MeshEdge
	if err := protojson.Unmarshal(data, &edge); err != nil {
		return err
	}
	e.MeshEdge = &edge
	return nil
}
