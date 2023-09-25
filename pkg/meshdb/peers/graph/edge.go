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
	"reflect"

	"github.com/dominikbraun/graph"
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
		Source: NodeID(e.Source),
		Target: NodeID(e.Target),
		Properties: graph.EdgeProperties{
			Weight:     int(e.Weight),
			Attributes: e.Attributes,
		},
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
