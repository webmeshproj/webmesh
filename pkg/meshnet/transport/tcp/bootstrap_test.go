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

package tcp

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/logging"
	"github.com/webmeshproj/webmesh/pkg/meshnet/transport"
)

// TestBootstrapTransport tests the basic leader-election functionality of the bootstrap transport.
// It should not be run in parallel with other tests to avoid port conflicts.
func TestBootstrapTransport(t *testing.T) {
	ctx := context.Background()
	nooplog := logging.NewLogger("", "")
	ctx = context.WithLogger(ctx, nooplog)

	// Test a single node transport.
	t.Run("SingleNode", func(t *testing.T) {
		transport := NewBootstrapTransport(BootstrapTransportOptions{
			NodeID:          "node",
			Addr:            "127.0.0.1:10000",
			Advertise:       "127.0.0.1:10000",
			MaxPool:         1,
			Timeout:         time.Millisecond * 100,
			ElectionTimeout: time.Millisecond * 100,
			Credentials:     []grpc.DialOption{},
		})
		// Do the leader election
		leader, rt, err := transport.LeaderElect(ctx)
		if err != nil {
			t.Fatalf("failed to leader elect: %v", err)
		}
		// Check that we became the leader.
		if !leader {
			t.Fatalf("expected to become leader")
		}
		// We should not get a round tripper back
		if rt != nil {
			t.Fatalf("expected no round tripper")
		}
	})

	// We'll reuse these methods for the rest of the tests.
	var wg sync.WaitGroup
	var leaderCount atomic.Int32
	runTransport := func(t *testing.T, brt transport.BootstrapTransport) {
		defer wg.Done()
		// Do the leader election
		leader, rt, err := brt.LeaderElect(ctx)
		if err != nil {
			t.Errorf("failed to leader elect: %v", err)
			return
		}
		if leader {
			// If we became the leader we should not have a round tripper.
			if rt != nil {
				t.Error("transport1 became leader, expected no round tripper")
			}
			// Increment the leader count.
			leaderCount.Add(1)
		} else {
			// If we did not become the leader we should have a round tripper.
			if rt == nil {
				t.Error("transport1 did not become leader, expected round tripper")
			}
		}
	}

	// Test a two node transport.
	t.Run("TwoNode", func(t *testing.T) {
		// Create the first transport.
		transport1 := NewBootstrapTransport(BootstrapTransportOptions{
			NodeID:          "node1",
			Addr:            "127.0.0.1:10001",
			Advertise:       "127.0.0.1:10001",
			MaxPool:         1,
			Timeout:         time.Millisecond * 500,
			ElectionTimeout: time.Millisecond * 500,
			Credentials:     []grpc.DialOption{},
			Peers: map[string]BootstrapPeer{
				"node2": {
					NodeID:        "node2",
					AdvertiseAddr: "127.0.0.1:10002",
				},
			},
		})
		// Create the second transport.
		transport2 := NewBootstrapTransport(BootstrapTransportOptions{
			NodeID:          "node2",
			Addr:            "127.0.0.1:10002",
			Advertise:       "127.0.0.1:10002",
			MaxPool:         1,
			Timeout:         time.Millisecond * 500,
			ElectionTimeout: time.Millisecond * 500,
			Credentials:     []grpc.DialOption{},
			Peers: map[string]BootstrapPeer{
				"node1": {
					NodeID:        "node1",
					AdvertiseAddr: "127.0.0.1:10001",
				},
			},
		})

		// Start both transports, only one should become leader.
		wg = sync.WaitGroup{}
		leaderCount.Store(0)
		wg.Add(2)
		go runTransport(t, transport1)
		go runTransport(t, transport2)
		wg.Wait()
		// Only one transport should have become leader.
		if leaderCount.Load() != 1 {
			t.Errorf("expected one transport to become leader, got %d", leaderCount.Load())
		}
	})

	// Test a three node transport.
	t.Run("ThreeNode", func(t *testing.T) {
		transport1 := NewBootstrapTransport(BootstrapTransportOptions{
			NodeID:          "node1",
			Addr:            "127.0.0.1:10001",
			Advertise:       "127.0.0.1:10001",
			MaxPool:         1,
			Timeout:         time.Millisecond * 500,
			ElectionTimeout: time.Millisecond * 500,
			Credentials:     []grpc.DialOption{},
			Peers: map[string]BootstrapPeer{
				"node2": {
					NodeID:        "node2",
					AdvertiseAddr: "127.0.0.1:10002",
				},
				"node3": {
					NodeID:        "node3",
					AdvertiseAddr: "127.0.0.1:10003",
				},
			},
		})
		transport2 := NewBootstrapTransport(BootstrapTransportOptions{
			NodeID:          "node2",
			Addr:            "127.0.0.1:10002",
			Advertise:       "127.0.0.1:10002",
			MaxPool:         1,
			Timeout:         time.Millisecond * 500,
			ElectionTimeout: time.Millisecond * 500,
			Credentials:     []grpc.DialOption{},
			Peers: map[string]BootstrapPeer{
				"node1": {
					NodeID:        "node1",
					AdvertiseAddr: "127.0.0.1:10001",
				},
				"node3": {
					NodeID:        "node3",
					AdvertiseAddr: "127.0.0.1:10003",
				},
			},
		})
		transport3 := NewBootstrapTransport(BootstrapTransportOptions{
			NodeID:          "node3",
			Addr:            "127.0.0.1:10003",
			Advertise:       "127.0.0.1:10003",
			MaxPool:         1,
			Timeout:         time.Millisecond * 500,
			ElectionTimeout: time.Millisecond * 500,
			Credentials:     []grpc.DialOption{},
			Peers: map[string]BootstrapPeer{
				"node1": {
					NodeID:        "node1",
					AdvertiseAddr: "127.0.0.1:10001",
				},
				"node2": {
					NodeID:        "node2",
					AdvertiseAddr: "127.0.0.1:10002",
				},
			},
		})

		// Start both transports, only one should become leader.
		wg = sync.WaitGroup{}
		leaderCount.Store(0)
		wg.Add(3)
		go runTransport(t, transport1)
		go runTransport(t, transport2)
		go runTransport(t, transport3)
		wg.Wait()
		// Only one transport should have become leader.
		if leaderCount.Load() != 1 {
			t.Errorf("expected one transport to become leader, got %d", leaderCount.Load())
		}
	})
}
