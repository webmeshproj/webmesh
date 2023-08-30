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

	"github.com/webmeshproj/webmesh/pkg/net/transport"
	"github.com/webmeshproj/webmesh/pkg/net/transport/tcp"
	"github.com/webmeshproj/webmesh/pkg/raft"
	"github.com/webmeshproj/webmesh/pkg/storage/nutsdb"
)

// NewTestMesh creates a new test mesh and waits for it to be ready.
// The context is used to enforce startup timeouts.
func NewTestMesh(ctx context.Context) (Mesh, error) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	st := New(Config{
		NodeID: uuid.NewString(),
	})
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
	opts := raft.NewOptions(st.ID())
	opts.InMemory = true
	rft := raft.New(opts)
	if err := rft.Start(ctx, raft.StartOptions{
		Transport:   raftTransport,
		MeshStorage: storage,
		RaftStorage: storage,
	}); err != nil {
		return nil, err
	}
	if err := stor.Connect(ctx, ConnectOptions{
		Raft:                 rft,
		GRPCAdvertisePort:    8443,
		MeshDNSAdvertisePort: 53,
		Bootstrap: &BootstrapOptions{
			Transport:            transport.NewNullBootstrapTransport(),
			IPv4Network:          "172.16.0.0/12",
			MeshDomain:           "webmesh.internal",
			Admin:                "admin",
			DisableRBAC:          false,
			DefaultNetworkPolicy: "accept",
		},
	}); err != nil {
		return nil, err
	}
	return stor, nil
}
