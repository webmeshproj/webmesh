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
	"io"
	"log/slog"
	"time"

	"github.com/google/uuid"
	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/net/transport"
	"github.com/webmeshproj/webmesh/pkg/net/transport/tcp"
	"github.com/webmeshproj/webmesh/pkg/storage/nutsdb"
)

// NewTestMesh creates a new test mesh and waits for it to be ready.
// The context is used to enforce startup timeouts.
func NewTestMesh(ctx context.Context) (Mesh, error) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	st, err := New(newTestOptions())
	if err != nil {
		return nil, err
	}
	stor := st.(*meshStore)
	stor.testStore = true
	storage, err := nutsdb.New(nutsdb.Options{InMemory: true})
	if err != nil {
		return nil, err
	}
	raftTransport, err := tcp.NewRaftTransport(st, tcp.RaftTransportOptions{
		Addr:    ":0",
		MaxPool: 1,
		Timeout: time.Second,
	})
	if err != nil {
		return nil, err
	}
	if err := stor.Open(ctx, ConnectOptions{
		BootstrapTransport: transport.NewNullBootstrapTransport(),
		JoinRoundTripper:   nil,
		RaftTransport:      raftTransport,
		RaftStorage:        storage,
		MeshStorage:        storage,
		ForceBootstrap:     false,
		Features:           []v1.Feature{},
	}); err != nil {
		return nil, err
	}
	return stor, nil
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
