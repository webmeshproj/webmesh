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

// Package wgsecurity implements the libp2p security transport for webmesh.
package wgsecurity

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/pnet"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/core/sec"
	"github.com/libp2p/go-libp2p/p2p/net/upgrader"

	"github.com/webmeshproj/webmesh/pkg/context"
	wmcrypto "github.com/webmeshproj/webmesh/pkg/crypto"
	wmconfig "github.com/webmeshproj/webmesh/pkg/embed/libp2p/config"
	wmproto "github.com/webmeshproj/webmesh/pkg/embed/libp2p/protocol"
	"github.com/webmeshproj/webmesh/pkg/embed/libp2p/util"
	"github.com/webmeshproj/webmesh/pkg/net/endpoints"
	"github.com/webmeshproj/webmesh/pkg/net/wireguard"
	"github.com/webmeshproj/webmesh/pkg/util/netutil"
)

// Ensure we implement the interface
var _ sec.SecureTransport = (*SecureTransport)(nil)

// Constructor is a constructor for the SecureTransport.
type Constructor func(id protocol.ID, h host.Host, psk pnet.PSK, privkey crypto.PrivKey, muxers []upgrader.StreamMuxer) (sec.SecureTransport, error)

// SecureTransport provides a sec.SecureTransport that will automatically set up
// routes and compute addresses for peers as connections are opened.
type SecureTransport struct {
	peerID     peer.ID
	host       host.Host
	psk        pnet.PSK
	protocolID protocol.ID
	key        wmcrypto.PrivateKey
	eps        endpoints.PrefixList
	iface      wireguard.Interface
	muxerIDs   []protocol.ID
	log        *slog.Logger
	mu         sync.Mutex
}

// NewTransport returns a proper constructor interface for libp2p with the given options.
func NewTransport(opts wmconfig.Options) Constructor {
	return func(id protocol.ID, h host.Host, psk pnet.PSK, privkey crypto.PrivKey, muxers []upgrader.StreamMuxer) (sec.SecureTransport, error) {
		return New(id, h, psk, privkey, muxers, opts)
	}
}

// New is a standalone constructor for SecureTransport.
func New(id protocol.ID, host host.Host, psk pnet.PSK, privkey crypto.PrivKey, muxers []upgrader.StreamMuxer, opts wmconfig.Options) (*SecureTransport, error) {
	opts.Default()
	opts.Logger = opts.Logger.With("security", "webmesh")
	peerID, err := peer.IDFromPrivateKey(privkey)
	if err != nil {
		opts.Logger.Error("Failed to extract peer ID from private key", "error", err.Error())
		return nil, fmt.Errorf("failed to extract peer ID from private key: %w", err)
	}
	key, err := util.ToWebmeshPrivateKey(privkey)
	if err != nil {
		opts.Logger.Error("Failed to convert private key to webmesh key", "error", err.Error())
		return nil, fmt.Errorf("failed to convert private key to webmesh key: %w", err)
	}
	opts.Logger.Info("Creating webmesh secure transport", "peer-id", peerID.String())
	ctx := context.WithLogger(context.Background(), opts.Logger)
	var eps endpoints.PrefixList
	if opts.EndpointDetection != nil {
		eps, err = endpoints.Detect(ctx, *opts.EndpointDetection)
		if err != nil {
			return nil, fmt.Errorf("failed to detect public endpoints: %w", err)
		}
	}
	var lula netip.Prefix
	var laddr netip.Addr
	if len(psk) > 0 {
		// We are going to seed the ULA with the PSK.
		lula = netutil.GenerateULAWithSeed(psk)
		laddr = netutil.AssignToPrefix(lula, key.PublicKey()).Addr()
	} else {
		lula, laddr = netutil.GenerateULAWithKey(key.PublicKey())
	}
	opts.Logger.Info("Generated local ULA network, configuring WireGuard",
		"local-ula", lula.String(), "local-addr", laddr.String())
	wgopts := wireguard.Options{
		NodeID:      peerID.String(),
		ListenPort:  int(opts.Config.ListenPort),
		Name:        opts.Config.InterfaceName,
		ForceName:   opts.Config.ForceInterfaceName,
		MTU:         opts.Config.MTU,
		NetworkV6:   lula,
		AddressV6:   netip.PrefixFrom(laddr, wmproto.PrefixSize),
		DisableIPv4: true,
	}
	iface, err := wireguard.New(ctx, &wgopts)
	if err != nil {
		return nil, fmt.Errorf("failed to create wireguard interface: %w", err)
	}
	// Add a route for the entire ULA network to the interface.
	err = iface.AddRoute(ctx, lula)
	if err != nil {
		defer func() { _ = iface.Close(ctx) }()
		return nil, fmt.Errorf("failed to add route for ULA network: %w", err)
	}
	muxerIDs := make([]protocol.ID, 0, len(muxers))
	for _, m := range muxers {
		muxerIDs = append(muxerIDs, m.ID)
	}
	// Set the negotiation handler for the security protocol.
	sec := &SecureTransport{
		peerID:     peerID,
		host:       host,
		psk:        psk,
		protocolID: id,
		key:        key,
		eps:        eps,
		iface:      iface,
		muxerIDs:   muxerIDs,
		log:        opts.Logger.With("protocol", id, "component", "secure-transport"),
	}
	return sec, nil
}

// ID is the protocol ID of the security protocol.
func (st *SecureTransport) ID() protocol.ID { return st.protocolID }

// Close closes the transport.
func (st *SecureTransport) Close() error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.iface == nil {
		return nil
	}
	err := st.iface.Close(context.Background())
	st.iface = nil
	return err
}

// SetKey sets the private key to use for securing connections.
func (st *SecureTransport) SetKey(key wmcrypto.PrivateKey) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.key = key
}

// SetInterface sets the wireguard interface to use for securing connections.
func (st *SecureTransport) SetInterface(iface wireguard.Interface) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.iface = iface
}

// SetEndpoints sets the endpoints to use for securing connections.
func (st *SecureTransport) SetEndpoints(eps endpoints.PrefixList) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.eps = eps
}

// WireGuardAddrPorts returns the exposed endpoints for our wireguard interface.
func (st *SecureTransport) WireGuardAddrPorts() []string {
	var out []string
	wgport, _ := st.iface.ListenPort()
	addrports := st.eps.AddrPorts(uint16(wgport))
	for _, ap := range addrports {
		out = append(out, ap.String())
	}
	return out
}

// SecureInbound secures an inbound connection. If p is empty, connections from any peer are accepted.
func (st *SecureTransport) SecureInbound(ctx context.Context, insecure net.Conn, p peer.ID) (sec.SecureConn, error) {
	st.log.Info("Securing inbound connection")
	ctx = context.WithLogger(ctx, st.log)
	c, err := st.NewSecureConn(ctx, insecure, p)
	if err != nil {
		st.log.Error("Failed to secure connection", "error", err.Error())
		return nil, fmt.Errorf("failed to secure connection: %w", err)
	}
	err = c.ConfigureInterface(ctx)
	if err != nil {
		st.log.Error("Failed to configure wireguard interface", "error", err.Error())
		return nil, fmt.Errorf("failed to configure wireguard interface: %w", err)
	}
	err = c.ExchangeEndpoints(ctx)
	if err != nil {
		st.log.Error("Failed to negotiate endpoints", "error", err.Error())
		return nil, fmt.Errorf("failed to negotiate endpoints: %w", err)
	}
	return c, nil
}

// SecureOutbound secures an outbound connection.
func (st *SecureTransport) SecureOutbound(ctx context.Context, insecure net.Conn, p peer.ID) (sec.SecureConn, error) {
	// Extract the peers public key from the peer ID.
	st.log.Info("Securing outbound connection")
	ctx = context.WithLogger(ctx, st.log)
	c, err := st.NewSecureConn(ctx, insecure, p)
	if err != nil {
		st.log.Error("Failed to secure connection", "error", err.Error())
		return nil, fmt.Errorf("failed to secure connection: %w", err)
	}
	err = c.ConfigureInterface(ctx)
	if err != nil {
		st.log.Error("Failed to configure wireguard interface", "error", err.Error())
		return nil, fmt.Errorf("failed to configure wireguard interface: %w", err)
	}
	err = c.ExchangeEndpoints(ctx)
	if err != nil {
		st.log.Error("Failed to negotiate endpoints", "error", err.Error())
		return nil, fmt.Errorf("failed to negotiate endpoints: %w", err)
	}
	return c, nil
}
