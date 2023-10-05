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

package meshnode

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/multiformats/go-multiaddr"
	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/meshnet"
	"github.com/webmeshproj/webmesh/pkg/meshnet/transport"
	"github.com/webmeshproj/webmesh/pkg/meshnet/transport/libp2p"
	"github.com/webmeshproj/webmesh/pkg/plugins"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/providers/raftstorage"
)

// ConnectOptions are options for opening the connection to the mesh.
type ConnectOptions struct {
	// StorageProvider is the underlying storage provider to use.
	StorageProvider storage.Provider
	// Features are the features to broadcast to others in the mesh.
	Features []*v1.FeaturePort
	// Plugins is a map of plugins to use.
	Plugins map[string]plugins.Plugin
	// JoinRoundTripper is the round tripper to use for joining the mesh.
	JoinRoundTripper transport.JoinRoundTripper
	// NetworkOptions are options for the network manager
	NetworkOptions meshnet.Options
	// Discovery are options for broadcasting to others to join the mesh
	// via this node. It can be turned on later if needed.
	Discovery *libp2p.AnnounceOptions
	// MaxJoinRetries is the maximum number of join retries.
	MaxJoinRetries int
	// GRPCAdvertisePort is the port to advertise for gRPC connections.
	GRPCAdvertisePort int
	// MeshDNSAdvertisePort is the port to advertise for MeshDNS connections.
	MeshDNSAdvertisePort int
	// PrimaryEndpoint is a publicly accessible address to broadcast as the
	// primary endpoint for this node. This is used for discovery and
	// connection into the mesh. If left unset, the node will be assumed to be
	// behind a NAT.
	PrimaryEndpoint netip.Addr
	// WireGuardEndpoints are endpoints to advertise for WireGuard connections.
	WireGuardEndpoints []netip.AddrPort
	// RequestVote requests a vote in Raft elections.
	RequestVote bool
	// RequestObserver requests to be an observer in Raft elections.
	RequestObserver bool
	// Routes are additional routes to broadcast to the mesh.
	Routes []netip.Prefix
	// DirectPeers are a map of peers to connect to directly. The values
	// are the prefered transport to use.
	DirectPeers map[string]v1.ConnectProtocol
	// Bootstrap are options for bootstrapping the mesh when connecting for
	// the first time.
	Bootstrap *BootstrapOptions
	// PreferIPv6 is true if IPv6 should be preferred over IPv4.
	PreferIPv6 bool
	// Multiaddrs are the multiaddrs to advertise for this node.
	Multiaddrs []multiaddr.Multiaddr
}

// BootstrapOptions are options for bootstrapping the mesh when connecting for
// the first time.
type BootstrapOptions struct {
	// Transport is the transport to use for bootstrapping the mesh.
	Transport transport.BootstrapTransport
	// IPv4Network is the IPv4 Network to use for the mesh. Defaults to
	// DefaultIPv4Network.
	IPv4Network string
	// MeshDomain is the domain of the mesh network. Defaults to
	// DefaultMeshDomain.
	MeshDomain string
	// Admin is the ID of the administrator node. Defaults to "admin".
	Admin string
	// Servers are other node IDs that were bootstrapped with the same
	// transport.
	Servers []string
	// Voters are additional node IDs to assign voter permissions to.
	Voters []string
	// DisableRBAC disables RBAC for the mesh.
	DisableRBAC bool
	// DefaultNetworkPolicy is the default network policy for the mesh.
	// If empty, DefaultNetworkPolicy will be used.
	DefaultNetworkPolicy string
	// Force is true if the node should force bootstrap.
	Force bool
}

// Connect opens the connection to the mesh.
func (s *meshStore) Connect(ctx context.Context, opts ConnectOptions) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.open.Load() {
		return ErrOpen
	}
	s.storage = opts.StorageProvider
	log := s.log
	log.Debug("Connecting to mesh network", slog.Any("options", opts))

	// If our key is still nil, generate an ephemeral key.
	if s.key == nil {
		log.Debug("Generating ephemeral key pair")
		key, err := crypto.GenerateKey()
		if err != nil {
			return fmt.Errorf("generate key: %w", err)
		}
		s.key = key
	}

	// Create the plugin manager
	pluginopts := plugins.Options{
		Storage:               s.Storage(),
		Plugins:               opts.Plugins,
		DisableDefaultIPAM:    s.opts.DisableDefaultIPAM,
		DefaultIPAMStaticIPv4: s.opts.DefaultIPAMStaticIPv4,
	}
	s.plugins, err = plugins.NewManager(ctx, pluginopts)
	if err != nil {
		return fmt.Errorf("failed to load plugins: %w", err)
	}
	// If we are using the built-in storage, register the observer
	if raft, ok := s.storage.(*raftstorage.Provider); ok {
		raft.OnObservation(s.newObserver())
	}
	// Start serving storage queries for plugins.
	handleErr := func(cause error) error {
		s.kvSubCancel()
		log.Error("Failed to open mesh connection", slog.String("error", err.Error()))
		perr := s.plugins.Close()
		if perr != nil {
			log.Error("Failed to close plugin manager", slog.String("error", perr.Error()))
		}
		return cause
	}
	// Create the network manager
	opts.NetworkOptions.StoragePort = int(s.storage.ListenPort())
	s.nw = meshnet.New(s.Storage().MeshDB(), opts.NetworkOptions, s.ID())
	if opts.Bootstrap != nil {
		// Attempt bootstrap.
		if err = s.bootstrap(ctx, opts); err != nil {
			return handleErr(fmt.Errorf("bootstrap: %w", err))
		}
	} else if opts.JoinRoundTripper != nil {
		// Attempt to join the cluster.
		err = s.join(ctx, opts)
		if err != nil {
			return handleErr(fmt.Errorf("join: %w", err))
		}
	} else {
		// We neither had the bootstrap flag nor any join flags set.
		// This means we are possibly a single node cluster.
		// Recover our previous wireguard configuration and start up.
		if err := s.recoverWireguard(ctx); err != nil {
			return fmt.Errorf("recover wireguard: %w", err)
		}
	}
	// At this point we are open for business.
	s.open.Store(true)
	if s.testStore {
		return nil
	}
	// Register an update hook to watch for network changes.
	if s.storage.Consensus().IsMember() {
		s.log.Debug("Subscribing to peer updates from local storage")
		s.kvSubCancel, err = s.storage.MeshDB().Peers().Subscribe(context.Background(), s.onPeerUpdate)
		if err != nil {
			return handleErr(fmt.Errorf("subscribe: %w", err))
		}
	} else {
		// Otherwise we are going to subscibe to peer updates from the network leader
		s.log.Debug("Subscribing to peer updates from the network")
		var subctx context.Context
		subctx, s.kvSubCancel = context.WithCancel(context.Background())
		go func() {
			for {
				s.log.Debug("Dialing network leader for membership updates")
				c, err := s.DialLeader(subctx)
				if err != nil {
					s.log.Error("Failed to dial leader for membership updates", slog.String("error", err.Error()))
					if subctx.Err() != nil {
						return
					}
					time.Sleep(time.Second)
					continue
				}
				defer c.Close()
				s.log.Debug("Subscribing to peer updates from the network leader")
				stream, err := v1.NewMembershipClient(c).SubscribePeers(subctx, &v1.SubscribePeersRequest{
					Id: s.ID().String(),
				})
				if err != nil {
					s.log.Error("Failed to subscribe to peers", slog.String("error", err.Error()))
					if subctx.Err() != nil {
						return
					}
					time.Sleep(time.Second)
					continue
				}
				defer func() {
					_ = stream.CloseSend()
				}()
				for {
					peers, err := stream.Recv()
					if err != nil {
						s.log.Error("Failed to receive peer updates", slog.String("error", err.Error()))
						if subctx.Err() != nil {
							return
						}
						time.Sleep(time.Second)
						break
					}
					s.log.Debug("Received peer updates", slog.Any("peers", peers))
					err = s.nw.Peers().Refresh(subctx, peers.Peers)
					if err != nil {
						s.log.Error("Failed to refresh peers", slog.String("error", err.Error()))
						if subctx.Err() != nil {
							return
						}
						time.Sleep(time.Second)
						break
					}
				}
			}
		}()
	}
	if opts.Discovery != nil {
		err = s.Discovery().AnnounceToDHT(ctx, *opts.Discovery)
		if err != nil {
			return handleErr(fmt.Errorf("announce dht: %w", err))
		}
	}
	return nil
}

func (s *meshStore) recoverWireguard(ctx context.Context) error {
	if s.testStore {
		return nil
	}
	var meshnetworkv4, meshnetworkv6 netip.Prefix
	var err error
	state := s.Storage().MeshDB().MeshState()
	if !s.opts.DisableIPv6 {
		meshnetworkv6, err = state.GetIPv6Prefix(ctx)
		if err != nil {
			return fmt.Errorf("get ula prefix: %w", err)
		}
	}
	if !s.opts.DisableIPv4 {
		meshnetworkv4, err = state.GetIPv4Prefix(ctx)
		if err != nil {
			return fmt.Errorf("get ipv4 prefix: %w", err)
		}
	}
	p := s.Storage().MeshDB().Peers()
	self, err := p.Get(ctx, s.ID())
	if err != nil {
		return fmt.Errorf("get self peer: %w", err)
	}
	opts := meshnet.StartOptions{
		Key: s.key,
		AddressV4: func() netip.Prefix {
			if s.opts.DisableIPv4 {
				return netip.Prefix{}
			}
			return self.PrivateAddrV4()
		}(),
		AddressV6: func() netip.Prefix {
			if s.opts.DisableIPv6 {
				return netip.Prefix{}
			}
			return self.PrivateAddrV6()
		}(),
		NetworkV4: meshnetworkv4,
		NetworkV6: meshnetworkv6,
	}
	err = s.nw.Start(ctx, opts)
	if err != nil {
		return fmt.Errorf("configure wireguard: %w", err)
	}
	wgpeers, err := meshnet.WireGuardPeersFor(ctx, s.Storage().MeshDB(), s.ID())
	if err != nil {
		return fmt.Errorf("get wireguard peers: %w", err)
	}
	return s.nw.Peers().Refresh(ctx, wgpeers)
}
