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

// Package rpcdb provides a meshdb that operates over RPC.
package rpcdb

import (
	"context"
	"sync"

	v1 "github.com/webmeshproj/api/go/v1"
	"google.golang.org/grpc"

	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/meshdb"
)

// Open opens a new mesh database over a Querier interface.
func Open(q Querier) storage.MeshDB {
	return meshdb.New(&RPCDataStore{q})
}

// OpenServer opens a new mesh database over a QueryServer interface.
func OpenServer(s QueryServer) storage.MeshDB {
	return Open(QuerierFromServer(s))
}

// OpenKV opens a new key-value store connection over a Querier interface.
func OpenKV(q Querier) storage.MeshStorage {
	return &KVStorage{q}
}

// OpenKVServer opens a new key-value store connection over a QueryServer interface.
func OpenKVServer(s QueryServer) storage.MeshStorage {
	return OpenKV(QuerierFromServer(s))
}

// Querier is an interface for invoking the query RPC.
type Querier interface {
	// Query invokes the query RPC.
	Query(ctx context.Context, query *v1.QueryRequest) (*v1.QueryResponse, error)
}

// QuerierFunc is a function that implements the Querier interface.
type QuerierFunc func(ctx context.Context, query *v1.QueryRequest) (*v1.QueryResponse, error)

// Query invokes the query RPC.
func (f QuerierFunc) Query(ctx context.Context, query *v1.QueryRequest) (*v1.QueryResponse, error) {
	return f(ctx, query)
}

// QueryServer is a generic streaming querier interface.
type QueryServer interface {
	// The underlying gRPC stream.
	grpc.ServerStream
	// Send sends a query request to the plugin.
	Send(*v1.QueryRequest) error
	// Recv receives a query result from the plugin.
	Recv() (*v1.QueryResponse, error)
}

// QuerierFromServer returns a Querier from a QueryServer.
func QuerierFromServer(s QueryServer) Querier {
	var mu sync.Mutex
	return QuerierFunc(func(ctx context.Context, query *v1.QueryRequest) (*v1.QueryResponse, error) {
		mu.Lock()
		defer mu.Unlock()
		err := s.Send(query)
		if err != nil {
			return nil, err
		}
		resp := make(chan *v1.QueryResponse, 1)
		errs := make(chan error, 1)
		go func() {
			r, err := s.Recv()
			if err != nil {
				errs <- err
				return
			}
			resp <- r
		}()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case err := <-errs:
			return nil, err
		case r := <-resp:
			return r, nil
		}
	})
}
