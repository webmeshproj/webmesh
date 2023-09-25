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
