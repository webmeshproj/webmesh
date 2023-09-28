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

package raftstorage

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/meshnet/transport"
	"github.com/webmeshproj/webmesh/pkg/meshnet/transport/tcp"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/testutil"
)

func TestInMemoryProviderConformance(t *testing.T) {
	builder := &builder{}
	testutil.TestStorageProviderConformance(context.Background(), t, builder.newProviders)
}

type builder struct{}

func (b *builder) newProviders(t *testing.T, count int) []storage.Provider {
	var out []storage.Provider
	for i := 0; i < count; i++ {
		transport, err := tcp.NewRaftTransport(nil, tcp.RaftTransportOptions{
			Addr:    "[::]:0",
			MaxPool: 10,
			Timeout: time.Second,
		})
		if err != nil {
			t.Fatalf("failed to create raft transport: %v", err)
		}
		out = append(out, NewProvider(newTestOptions(transport)))
	}

	return out
}

func newTestOptions(transport transport.RaftTransport) Options {
	return Options{
		NodeID:             uuid.NewString(),
		Transport:          transport,
		InMemory:           true,
		ConnectionTimeout:  time.Millisecond * 500,
		HeartbeatTimeout:   time.Millisecond * 500,
		ElectionTimeout:    time.Millisecond * 500,
		LeaderLeaseTimeout: time.Millisecond * 500,
		ApplyTimeout:       time.Second * 10,
		CommitTimeout:      time.Second * 10,
		SnapshotInterval:   time.Minute,
		SnapshotThreshold:  5,
		MaxAppendEntries:   15,
		SnapshotRetention:  3,
		ObserverChanBuffer: 100,
		BarrierThreshold:   1,
		LogLevel:           "",
	}
}
