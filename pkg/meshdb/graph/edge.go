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

package graph

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/dominikbraun/graph"
	"github.com/google/go-cmp/cmp"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// ErrEdgeNotFound is returned when an edge is not found.
var ErrEdgeNotFound = graph.ErrEdgeNotFound

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

// PutInto puts the MeshEdge into the given graph.
func (e MeshEdge) PutInto(g Graph) error {
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
		if !cmp.Equal(graphEdge.Properties.Attributes, e.Attributes) {
			return g.UpdateEdge(e.SourceID(), e.TargetID(), opts...)
		}
		if graphEdge.Properties.Weight != int(e.Weight) {
			return g.UpdateEdge(e.SourceID(), e.TargetID(), opts...)
		}
		return nil
	}
	if !errors.Is(err, ErrEdgeNotFound) {
		return fmt.Errorf("get edge: %w", err)
	}
	err = g.AddEdge(e.SourceID(), e.TargetID(), opts...)
	if err != nil && !errors.Is(err, graph.ErrEdgeAlreadyExists) {
		return fmt.Errorf("add edge: %w", err)
	}
	return nil
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
