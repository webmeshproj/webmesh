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

package mesh

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"

	"github.com/webmeshproj/webmesh/pkg/net/transport"
	"github.com/webmeshproj/webmesh/pkg/storage/memory"
)

// NewTestMesh creates a new test mesh and waits for it to be ready.
// The context is used to enforce startup timeouts.
func NewTestMesh(ctx context.Context) (Mesh, error) {
	st, err := New(newTestOptions())
	if err != nil {
		return nil, err
	}
	stor := st.(*meshStore)
	stor.testStore = true
	raftStorage := memory.NewRaftStorage()
	meshStorage := memory.NewMeshStorage()
	transport, err := transport.NewRaftTCPTransport(st, transport.TCPTransportOptions{
		Addr:    ":0",
		MaxPool: 1,
		Timeout: time.Second,
	})
	if err != nil {
		return nil, err
	}
	if err := stor.Open(ctx, &ConnectOptions{
		RaftTransport: transport,
		RaftStorage:   raftStorage,
		MeshStorage:   meshStorage,
	}); err != nil {
		return nil, err
	}
	return stor, nil
}

// NewTestCluster creates a new test cluster and waits for it to be ready.
// The context is used to enforce startup timeouts. Clusters cannot be
// created in parallel without specifying unique raft ports. If startPort
// is 0, a default port will be used. The number of nodes must be greater
// than 0.
func NewTestCluster(ctx context.Context, numNodes int, startPort int) ([]Mesh, error) {
	const defaultStartPort = 10000
	if startPort == 0 {
		startPort = defaultStartPort
	}
	if numNodes < 1 {
		return nil, errors.New("invalid number of nodes")
	}
	bootstrapServers := make(map[string]string)
	for i := 0; i < numNodes; i++ {
		nodeID := fmt.Sprintf("node-%d", i)
		bootstrapServers[nodeID] = fmt.Sprintf("127.0.0.1:%d", startPort+i)
	}
	opts := make([]*Options, numNodes)
	for i := 0; i < numNodes; i++ {
		thisID := fmt.Sprintf("node-%d", i)
		thisAddr := fmt.Sprintf("127.0.0.1:%d", startPort+i)
		opts[i] = newTestOptions()
		opts[i].Mesh.NodeID = thisID
		opts[i].Bootstrap.AdvertiseAddress = thisAddr
		opts[i].Bootstrap.Servers = bootstrapServers
		opts[i].Raft.ListenAddress = thisAddr
	}
	stores := make([]Mesh, numNodes)
	for i := 0; i < numNodes; i++ {
		st, err := New(opts[i])
		if err != nil {
			return nil, err
		}
		stor := st.(*meshStore)
		stor.testStore = true
		stores[i] = stor
	}
	g, ctx := errgroup.WithContext(ctx)
	for i := 0; i < numNodes; i++ {
		i := i
		g.Go(func() error {
			if err := stores[i].Open(ctx, nil); err != nil {
				return err
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return stores, nil
}

func newTestOptions() *Options {
	opts := NewDefaultOptions()
	opts.Raft.ConnectionTimeout = 100 * time.Millisecond
	opts.Raft.HeartbeatTimeout = 100 * time.Millisecond
	opts.Raft.ElectionTimeout = 100 * time.Millisecond
	opts.Raft.LeaderLeaseTimeout = 100 * time.Millisecond
	opts.Raft.ListenAddress = ":0"
	opts.Raft.InMemory = true
	opts.TLS.Insecure = true
	opts.Bootstrap.Enabled = true
	opts.Mesh.NodeID = uuid.NewString()
	return opts
}
