//go:build !wasm

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
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/config"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/record"
	"github.com/multiformats/go-multiaddr"
	mnet "github.com/multiformats/go-multiaddr/net"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/crypto"
)

// Host is an interface that provides facilities for connecting to peers over libp2p.
type Host interface {
	// ID returns the peer ID of the host.
	ID() peer.ID
	// Host is the underlying libp2p host.
	Host() host.Host
	// AddAddrs adds the given addresses to the host's peerstore.
	AddAddrs(addrs []multiaddr.Multiaddr, id peer.ID, ttl time.Duration) error
	// SignAddrs creates an envelope for this host's peer ID and addresses.
	SignAddrs(seq uint64) (*record.Envelope, error)
	// ConsumePeerRecord consumes a peer record and adds it to the peerstore.
	ConsumePeerRecord(rec *record.Envelope, ttl time.Duration) error
	// RPCListener creates and returns a new net.Listener listening for RPC connections.
	// This should only ever be called once per host. The host will be closed when the
	// listener is closed.
	RPCListener() net.Listener
	// Close closes the host and its DHT.
	Close(ctx context.Context) error
}

// HostOptions are options for creating a new libp2p host.
type HostOptions struct {
	// Key is the key to use for identification. If left empty, an ephemeral
	// key is generated.
	Key crypto.PrivateKey
	// BootstrapPeers is a list of bootstrap peers to use for the DHT when
	// creating a discovery host. If empty or nil, the default bootstrap
	// peers will be used.
	BootstrapPeers []multiaddr.Multiaddr
	// Options are options for configuring the libp2p host.
	Options []config.Option
	// LocalAddrs is a list of local addresses to announce the host with.
	// If empty or nil, the default local addresses will be used.
	LocalAddrs []multiaddr.Multiaddr
	// ConnectTimeout is the timeout for connecting to peers when bootstrapping.
	ConnectTimeout time.Duration
	// UncertifiedPeerstore uses an uncertified peerstore for the host.
	// This is useful for testing or when using the host to dial pre-trusted
	// peers.
	UncertifiedPeerstore bool
	// NoFallbackDefaults disables the use of fallback defaults when creating
	// the host. This is useful for testing.
	NoFallbackDefaults bool
}

// MarshalJSON implements json.Marshaler.
func (o HostOptions) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"key":            "redacted",
		"bootstrapPeers": o.BootstrapPeers,
		"localAddrs":     o.LocalAddrs,
		"connectTimeout": o.ConnectTimeout,
	})
}

// NewHost creates a new libp2p host with the given options.
func NewHost(ctx context.Context, opts HostOptions) (Host, error) {
	if opts.Key != nil {
		opts.Options = append(opts.Options, libp2p.Identity(opts.Key.AsPrivKey()))
	}
	if len(opts.LocalAddrs) > 0 {
		opts.Options = append(opts.Options, libp2p.ListenAddrs(opts.LocalAddrs...))
	}
	if opts.ConnectTimeout > 0 {
		opts.Options = append(opts.Options, libp2p.WithDialTimeout(opts.ConnectTimeout))
	}
	if opts.UncertifiedPeerstore {
		ps, err := NewUncertifiedPeerstore()
		if err != nil {
			return nil, fmt.Errorf("new uncertified peerstore: %w", err)
		}
		opts.Options = append(opts.Options, libp2p.Peerstore(ps))
	}
	if !opts.NoFallbackDefaults {
		opts.Options = append(opts.Options, libp2p.FallbackDefaults)
	}
	host, err := libp2p.New(opts.Options...)
	if err != nil {
		return nil, fmt.Errorf("new libp2p host: %w", err)
	}
	return wrapHost(host), nil
}

type libp2pHost struct {
	host      host.Host
	liscancel func()
}

// wrapHost wraps a libp2p host.
func wrapHost(host host.Host) Host {
	return &libp2pHost{host: host}
}

// ID returns the peer ID of the host.
func (h *libp2pHost) ID() peer.ID {
	return h.host.ID()
}

// Host returns the underlying libp2p host.
func (h *libp2pHost) Host() host.Host {
	return h.host
}

// AddAddrs adds the given addresses to the host's peerstore. It will also
// attempt to extract the public key from the peer ID and add it to the peerstore.
func (h *libp2pHost) AddAddrs(addrs []multiaddr.Multiaddr, id peer.ID, ttl time.Duration) error {
	if ttl == 0 {
		ttl = peerstore.PermanentAddrTTL
	}
	ps := h.host.Peerstore()
	pubkey, err := id.ExtractPublicKey()
	if err != nil {
		return fmt.Errorf("extract public key: %w", err)
	}
	err = ps.AddPubKey(id, pubkey)
	if err != nil {
		return fmt.Errorf("add public key: %w", err)
	}
	ps.AddAddrs(id, addrs, ttl)
	return nil
}

// SignAddrs creates an envelope for this host's peer ID and addresses.
func (h *libp2pHost) SignAddrs(seq uint64) (*record.Envelope, error) {
	rec := &peer.PeerRecord{
		PeerID: h.Host().ID(),
		Addrs:  h.Host().Addrs(),
		Seq:    seq,
	}
	return record.Seal(rec, h.Host().Peerstore().PrivKey(h.Host().ID()))
}

// ConsumePeerRecord consumes a peer record and adds it to the peerstore.
func (h *libp2pHost) ConsumePeerRecord(rec *record.Envelope, ttl time.Duration) error {
	if ttl == 0 {
		ttl = peerstore.PermanentAddrTTL
	}
	cab, ok := peerstore.GetCertifiedAddrBook(h.host.Peerstore())
	if !ok {
		return fmt.Errorf("no certified address book")
	}
	ok, err := cab.ConsumePeerRecord(rec, ttl)
	if err != nil {
		return fmt.Errorf("consume peer record: %w", err)
	}
	if !ok {
		return fmt.Errorf("consume peer record returned false")
	}
	return nil
}

// RPCListener creates and returns a new net.Listener listening for RPC connections.
// This should only ever be called once per host.
func (h *libp2pHost) RPCListener() net.Listener {
	ch := make(chan net.Conn, 100)
	ctx, cancel := context.WithCancel(context.Background())
	h.host.SetStreamHandler(RPCProtocol, func(stream network.Stream) {
		ch <- NewConnFromStream(stream)
	})
	h.liscancel = cancel
	return &hostRPCListener{
		h:       h,
		close:   cancel,
		closec:  ctx.Done(),
		acceptc: ch,
	}
}

// Close closes the host and shuts down all listeners.
func (h *libp2pHost) Close(ctx context.Context) error {
	if h.liscancel != nil {
		h.liscancel()
	}
	return h.host.Close()
}

type hostRPCListener struct {
	h       Host
	close   func()
	closec  <-chan struct{}
	acceptc chan net.Conn
}

// Accept waits for and returns the next connection to the listener.
func (h *hostRPCListener) Accept() (net.Conn, error) {
	select {
	case <-h.closec:
		return nil, net.ErrClosed
	case conn := <-h.acceptc:
		return conn, nil
	}
}

// Close closes the listener and underlying host.
func (h *hostRPCListener) Close() error {
	h.close()
	return h.h.Close(context.Background())
}

// Addr returns the listener's network address.
func (h *hostRPCListener) Addr() net.Addr {
	// Just return the first address.
	addrs := h.h.Host().Addrs()
	if len(addrs) == 0 {
		// This should never happen
		return nil
	}
	addr, _ := mnet.ToNetAddr(addrs[0])
	return addr
}
