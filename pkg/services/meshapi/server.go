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

// Package meshapi contains the webmesh Mesh API service.
package meshapi

import (
	"bytes"
	"context"

	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/webmeshproj/webmesh/pkg/meshdb/peers"
	"github.com/webmeshproj/webmesh/pkg/storage"
)

// Server is the webmesh Mesh service.
type Server struct {
	v1.UnimplementedMeshServer

	peers peers.Peers
}

// NewServer returns a new Server.
func NewServer(storage storage.MeshStorage) *Server {
	return &Server{peers: peers.New(storage)}
}

func (s *Server) GetNode(ctx context.Context, req *v1.GetNodeRequest) (*v1.MeshNode, error) {
	node, err := s.peers.Get(ctx, req.GetId())
	if err != nil {
		if err == peers.ErrNodeNotFound {
			return nil, status.Errorf(codes.NotFound, "node %s not found", req.GetId())
		}
		return nil, status.Errorf(codes.Internal, "failed to get node: %v", err)
	}
	return node.MeshNode, nil
}

func (s *Server) ListNodes(ctx context.Context, req *emptypb.Empty) (*v1.NodeList, error) {
	nodes, err := s.peers.List(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get node: %v", err)
	}
	out := make([]*v1.MeshNode, len(nodes))
	for i, node := range nodes {
		out[i] = node.MeshNode
	}
	return &v1.NodeList{
		Nodes: out,
	}, nil
}

func (s *Server) GetMeshGraph(ctx context.Context, _ *emptypb.Empty) (*v1.MeshGraph, error) {
	nodeIDs, err := s.peers.ListIDs(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list node IDs: %v", err)
	}
	edges, err := s.peers.Graph().Edges()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list edges: %v", err)
	}
	out := &v1.MeshGraph{
		Nodes: nodeIDs,
		Edges: make([]*v1.MeshEdge, len(edges)),
	}
	for i, edge := range edges {
		out.Edges[i] = &v1.MeshEdge{
			Source: edge.Source.String(),
			Target: edge.Target.String(),
			Weight: int32(edge.Properties.Weight),
		}
	}
	var buf bytes.Buffer
	err = s.peers.DrawDOTGraph(ctx, &buf)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to draw graph: %v", err)
	}
	out.Dot = buf.String()
	return out, nil
}
