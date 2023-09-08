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

package libp2p

import (
	"io"
	"net/netip"
	"strconv"
	"time"

	"github.com/hashicorp/raft"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/config"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/multiformats/go-multiaddr"
	"google.golang.org/grpc"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/net/transport"
)

// RaftTransportOptions are options for the TCP transport.
type RaftTransportOptions struct {
	// PSK is the pre-shared key to use as a rendezvous point for the DHT.
	PSK string
	// BootstrapPeers is a list of bootstrap peers to use for the DHT.
	// If empty or nil, the default bootstrap peers will be used.
	BootstrapPeers []multiaddr.Multiaddr
	// LocalAddrs is a list of local addresses to use for the host.
	// If empty or nil, the default local addresses will be used.
	LocalAddrs []multiaddr.Multiaddr
	// Options are options for configuring the libp2p host.
	Options []config.Option
	// DiscoveryTTL is the TTL to use for the discovery service.
	DiscoveryTTL time.Duration
	// ConnectTimeout is the timeout to use when connecting to a peer.
	ConnectTimeout time.Duration
	// LeaderDialer is the function that will be used to dial the leader.
	LeaderDialer transport.LeaderDialer
}

// NewRaftTransport creates a new Raft transport over the Kademlia DHT.
func NewRaftTransport(ctx context.Context, opts RaftTransportOptions) (raft.Transport, error) {
	host, err := NewHostAndDHT(ctx, HostOptions{
		BootstrapPeers: opts.BootstrapPeers,
		Options:        opts.Options,
		LocalAddrs:     opts.LocalAddrs,
		ConnectTimeout: opts.ConnectTimeout,
	})
	if err != nil {
		return nil, err
	}
	return &kadRaftTransport{
		RaftTransportOptions: opts,
		Host:                 host.Host(),
		dht:                  host.DHT(),
		rpcchan:              make(chan raft.RPC, 1),
	}, nil
}

type kadRaftTransport struct {
	RaftTransportOptions
	host.Host
	dht     *dht.IpfsDHT
	rpcchan chan raft.RPC
}

// Consumer returns a channel that can be used to
// consume and respond to RPC requests.
func (k *kadRaftTransport) Consumer() <-chan raft.RPC {
	return k.rpcchan
}

// LocalAddr is used to return our local address to distinguish from our peers.
func (k *kadRaftTransport) LocalAddr() raft.ServerAddress {
	return raft.ServerAddress(k.Host.Addrs()[0].String())
}

// AppendEntriesPipeline returns an interface that can be used to pipeline
// AppendEntries requests.
func (k *kadRaftTransport) AppendEntriesPipeline(id raft.ServerID, target raft.ServerAddress) (raft.AppendPipeline, error) {
	return &pipeline{
		transport: k,
		fchan:     make(chan raft.AppendFuture, 1),
	}, nil
}

// AppendEntries sends the appropriate RPC to the target node.
func (k *kadRaftTransport) AppendEntries(id raft.ServerID, target raft.ServerAddress, args *raft.AppendEntriesRequest, resp *raft.AppendEntriesResponse) error {
	return nil
}

// RequestVote sends the appropriate RPC to the target node.
func (k *kadRaftTransport) RequestVote(id raft.ServerID, target raft.ServerAddress, args *raft.RequestVoteRequest, resp *raft.RequestVoteResponse) error {
	return nil
}

// InstallSnapshot is used to push a snapshot down to a follower. The data is read from
// the ReadCloser and streamed to the client.
func (k *kadRaftTransport) InstallSnapshot(id raft.ServerID, target raft.ServerAddress, args *raft.InstallSnapshotRequest, resp *raft.InstallSnapshotResponse, data io.Reader) error {
	return nil
}

// EncodePeer is used to serialize a peer's address.
func (k *kadRaftTransport) EncodePeer(id raft.ServerID, addr raft.ServerAddress) []byte {
	return nil
}

// DecodePeer is used to deserialize a peer's address.
func (k *kadRaftTransport) DecodePeer([]byte) raft.ServerAddress {
	return ""
}

// SetHeartbeatHandler is used to setup a heartbeat handler
// as a fast-pass. This is to avoid head-of-line blocking from
// disk IO. If a Transport does not support this, it can simply
// ignore the call, and push the heartbeat onto the Consumer channel.
func (k *kadRaftTransport) SetHeartbeatHandler(cb func(rpc raft.RPC)) {

}

// TimeoutNow is used to start a leadership transfer to the target node.
func (k *kadRaftTransport) TimeoutNow(id raft.ServerID, target raft.ServerAddress, args *raft.TimeoutNowRequest, resp *raft.TimeoutNowResponse) error {
	return nil
}

// DialLeader opens a gRPC connection to the current leader.
func (k *kadRaftTransport) DialLeader(ctx context.Context) (*grpc.ClientConn, error) {
	return k.RaftTransportOptions.LeaderDialer.DialLeader(ctx)
}

// AddrPort returns the address and port the transport is listening on.
func (k *kadRaftTransport) AddrPort() netip.AddrPort {
	addr := k.Host.Addrs()[0]
	val, _ := addr.ValueForProtocol(multiaddr.P_TCP)
	if val != "" {
		port, _ := strconv.Atoi(val)
		return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port))
	}
	return netip.AddrPort{}
}

// Close closes the transport.
func (k *kadRaftTransport) Close() error {
	defer k.dht.Close()
	return k.Host.Close()
}

type pipeline struct {
	transport *kadRaftTransport
	fchan     chan raft.AppendFuture
}

// AppendEntries is used to add another request to the pipeline.
// The send may block which is an effective form of back-pressure.
func (p *pipeline) AppendEntries(args *raft.AppendEntriesRequest, resp *raft.AppendEntriesResponse) (raft.AppendFuture, error) {
	return &future{}, nil
}

// Consumer returns a channel that can be used to consume
// response futures when they are ready.
func (p *pipeline) Consumer() <-chan raft.AppendFuture { return p.fchan }

// Close closes the pipeline and cancels all inflight RPCs
func (p *pipeline) Close() error { return nil }

type future struct{}

// Start returns the time that the append request was started.
// It is always OK to call this method.
func (f *future) Start() time.Time { return time.Time{} }

// Request holds the parameters of the AppendEntries call.
// It is always OK to call this method.
func (f *future) Request() *raft.AppendEntriesRequest { return nil }

// Response holds the results of the AppendEntries call.
// This method must only be called after the Error
// method returns, and will only be valid on success.
func (f *future) Response() *raft.AppendEntriesResponse { return nil }

// Error holds the error result of the AppendEntries call.
// This method must only be called after the Error
// method returns, and will only be valid on failure.
func (f *future) Error() error { return nil }
