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
	"io"
	"log/slog"
	"time"

	"github.com/hashicorp/raft"
	"google.golang.org/grpc"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/net/transport"
	netutil "github.com/webmeshproj/webmesh/pkg/net/util"
)

// BootstrapTransportOptions are options for the TCP transport.
type BootstrapTransportOptions struct {
	// NodeID is the node id of the current node.
	NodeID string
	// Addr is the address to listen on.
	Addr string
	// Peers is a map of peer ids to addresses to dial.
	Peers map[string]BootstrapPeer
	// Advertise is the address to advertise.
	Advertise string
	// MaxPool is the maximum number of connections to pool.
	MaxPool int
	// Timeout is the timeout for dialing a connection.
	Timeout time.Duration
	// ElectionTimeout is the election timeout.
	ElectionTimeout time.Duration
	// Credentials are the credentials to use when dialing peers.
	Credentials []grpc.DialOption
}

// BootstrapPeer is a TCP bootstrap peer.
type BootstrapPeer struct {
	// NodeID is the peer id.
	NodeID string
	// AdvertiseAddr is the peer advertise address for leader election.
	AdvertiseAddr string
	// DialAddr is the peer dial address for after leader election.
	DialAddr string
}

// NewBootstrapTransport creates a new TCP transport listening on the given address.
// It uses a temporary in-memory raft cluster to perform leader election and then disposes
// of it.
func NewBootstrapTransport(opts BootstrapTransportOptions) transport.BootstrapTransport {
	return &bootstrapTransport{opts}
}

type bootstrapTransport struct {
	BootstrapTransportOptions
}

// LeaderElect implements BootstrapTransport.
func (t *bootstrapTransport) LeaderElect(ctx context.Context) (isLeader bool, rt transport.JoinRoundTripper, err error) {
	log := context.LoggerFrom(ctx).With("bootstrap-transport", "tcp")
	log.Debug("Starting bootstrap TCP transport")
	raftTransport, err := NewRaftTransport(nil, RaftTransportOptions{
		Addr:    t.Addr,
		MaxPool: t.MaxPool,
		Timeout: t.Timeout,
	})
	if err != nil {
		return false, nil, err
	}
	defer raftTransport.Close()

	// Build a suitable raft configuration
	rftOpts := raft.DefaultConfig()
	rftOpts.LocalID = raft.ServerID(t.NodeID)
	rftOpts.HeartbeatTimeout = t.ElectionTimeout
	rftOpts.ElectionTimeout = t.ElectionTimeout
	rftOpts.LeaderLeaseTimeout = t.ElectionTimeout
	rftOpts.CommitTimeout = t.ElectionTimeout
	rftOpts.SnapshotInterval = time.Minute
	rftOpts.SnapshotThreshold = 1024
	rftOpts.TrailingLogs = 1024
	rftOpts.LogOutput = io.Discard

	// Resolve our advertise address
	addr, err := netutil.ResolveTCPAddr(ctx, t.Advertise, 15)
	if err != nil {
		return false, nil, err
	}

	// Build the bootstrap configuration
	bootstrapConfig := raft.Configuration{
		Servers: []raft.Server{
			{
				ID:       rftOpts.LocalID,
				Address:  raft.ServerAddress(addr.String()),
				Suffrage: raft.Voter,
			},
		},
	}
	for id, peer := range t.Peers {
		// Resolve the peer address
		addr, err := netutil.ResolveTCPAddr(ctx, peer.AdvertiseAddr, 15)
		if err != nil {
			return false, nil, err
		}
		// Append the peer to the configuration
		bootstrapConfig.Servers = append(bootstrapConfig.Servers, raft.Server{
			ID:       raft.ServerID(id),
			Address:  raft.ServerAddress(addr.String()),
			Suffrage: raft.Voter,
		})
	}
	log.Debug("Starting bootstrap transport raft instance", slog.String("local-id", string(rftOpts.LocalID)), slog.Any("config", bootstrapConfig))
	rft, err := raft.NewRaft(rftOpts, &raft.MockFSM{}, raft.NewInmemStore(), raft.NewInmemStore(), raft.NewInmemSnapshotStore(), raftTransport)
	if err != nil {
		return false, nil, err
	}
	defer rft.Shutdown()

	// Attempt to bootstrap the cluster
	if err := rft.BootstrapCluster(bootstrapConfig).Error(); err != nil {
		if err == raft.ErrCantBootstrap {
			// The cluster was already bootstrapped (basically we took too long to get there)
			log.Debug("Bootstrap transport cluster already bootstrapped")
			// Build a transport that tries to join the other peers
			var opts RoundTripOptions
			for _, peer := range t.Peers {
				opts.Addrs = append(opts.Addrs, peer.DialAddr)
			}
			opts.Credentials = t.Credentials
			opts.AddressTimeout = t.Timeout
			return false, NewJoinRoundTripper(opts), transport.ErrAlreadyBootstrapped
		}
		return false, nil, err
	}

	// Wait for whoever is the leader
	log.Debug("Waiting for bootstrap transport leader election results")
	for {
		select {
		case <-ctx.Done():
			return false, nil, ctx.Err()
		case <-time.After(time.Millisecond * 250):
			addr, id := rft.LeaderWithID()
			if addr == "" {
				continue
			}
			if id == rftOpts.LocalID {
				// We won the election
				log.Debug("Bootstrap transport elected leader")
				return true, nil, nil
			}
			// We lost the election, build a transport to the leader
			log.Debug("Bootstrap transport is follower")
			leader := t.Peers[string(id)]
			return false, NewJoinRoundTripper(RoundTripOptions{
				Addrs:          []string{leader.DialAddr},
				Credentials:    t.Credentials,
				AddressTimeout: t.Timeout,
			}), nil
		}
	}
}
