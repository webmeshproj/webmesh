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
	"github.com/webmeshproj/webmesh/pkg/meshnet/transport/tcp"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/testutil"
)

func TestInMemoryProviderConformance(t *testing.T) {
	builder := func(ctx context.Context, t *testing.T) storage.Provider {
		transport, err := tcp.NewRaftTransport(nil, tcp.RaftTransportOptions{
			Addr:    "[::]:0",
			MaxPool: 1,
			Timeout: time.Second,
		})
		if err != nil {
			t.Fatalf("failed to create raft transport: %v", err)
		}
		opts := NewOptions(uuid.NewString(), transport)
		opts.InMemory = true
		p := NewProvider(opts)
		err = p.Start(ctx)
		if err != nil {
			t.Fatalf("failed to start provider: %v", err)
		}
		return p
	}
	testutil.TestStorageProviderConformance(context.Background(), t, builder)
}
