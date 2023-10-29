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

	v1 "github.com/webmeshproj/api/go/v1"
	"google.golang.org/grpc/codes"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

func TestGetEdge(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	server := newTestServer(t)

	// Place a dummy peer
	p := server.storage.MeshDB().Peers()
	err := p.Put(ctx, types.MeshNode{MeshNode: &v1.MeshNode{
		Id:        "foo",
		PublicKey: newEncodedPubKey(t),
	}})
	if err != nil {
		t.Errorf("Put() error = %v", err)
		return
	}
	err = p.Put(ctx, types.MeshNode{MeshNode: &v1.MeshNode{
		Id:        "bar",
		PublicKey: newEncodedPubKey(t),
	}})
	if err != nil {
		t.Errorf("Put() error = %v", err)
		return
	}
	// Place an edge from us to the dummy peer
	_, err = server.PutEdge(ctx, &v1.MeshEdge{
		Source: "foo",
		Target: "bar",
	})
	if err != nil {
		t.Errorf("PutEdge() error = %v", err)
		return
	}

	tc := []testCase[v1.MeshEdge]{
		{
			name: "no source node",
			code: codes.InvalidArgument,
			req:  &v1.MeshEdge{Source: "", Target: "bar"},
		},
		{
			name: "no target node",
			code: codes.InvalidArgument,
			req:  &v1.MeshEdge{Source: "foo", Target: ""},
		},
		{
			name: "non-existent edge",
			req:  &v1.MeshEdge{Source: "bar", Target: "bar"},
			code: codes.NotFound,
		},
		{
			name: "existing edge",
			req:  &v1.MeshEdge{Source: "foo", Target: "bar"},
			code: codes.OK,
		},
	}

	runTestCases(t, tc, server.GetEdge)
}
