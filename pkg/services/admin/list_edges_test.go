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

package admin

import (
	"testing"

	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/meshdb/peers"
)

func TestListEdges(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	server := newTestServer(t)

	// No empty condition

	// Place a dummy peer
	err := peers.New(server.storage.MeshStorage()).Put(ctx, &v1.MeshNode{
		Id:        "foo",
		PublicKey: newEncodedPubKey(t),
	})
	if err != nil {
		t.Errorf("Put() error = %v", err)
		return
	}
	err = peers.New(server.storage.MeshStorage()).Put(ctx, &v1.MeshNode{
		Id:        "bar",
		PublicKey: newEncodedPubKey(t),
	})
	if err != nil {
		t.Errorf("Put() error = %v", err)
		return
	}
	// Place an edge from us to the dummy peer
	_, err = server.PutEdge(ctx, &v1.MeshEdge{
		Source: "bar",
		Target: "foo",
	})
	if err != nil {
		t.Errorf("PutEdge() error = %v", err)
		return
	}

	// Verify edge is present
	edge, err := server.GetEdge(ctx, &v1.MeshEdge{
		Source: "bar",
		Target: "foo",
	})
	if err != nil {
		t.Errorf("GetEdge() error = %v", err)
		return
	}
	if edge.Source != "bar" {
		t.Errorf("edge.Source = %v, want %v", edge.Source, "bar")
	}
	if edge.Target != "foo" {
		t.Errorf("edge.Target = %v, want %v", edge.Target, "foo")
	}
}
