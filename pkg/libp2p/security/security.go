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

package security

import (
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"runtime"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/pnet"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/core/sec"
	mnet "github.com/multiformats/go-multiaddr/net"

	"github.com/webmeshproj/webmesh/pkg/context"
	wmcrypto "github.com/webmeshproj/webmesh/pkg/crypto"
	wmproto "github.com/webmeshproj/webmesh/pkg/libp2p/protocol"
	"github.com/webmeshproj/webmesh/pkg/libp2p/util"
	"github.com/webmeshproj/webmesh/pkg/meshnet/endpoints"
	"github.com/webmeshproj/webmesh/pkg/meshnet/system"
	netutil "github.com/webmeshproj/webmesh/pkg/meshnet/util"
	"github.com/webmeshproj/webmesh/pkg/meshnet/wireguard"
)

// Ensure we implement the interface
var _ sec.SecureTransport = (*SecureTransport)(nil)

// SecureTransport provides a sec.SecureTransport that will automatically set up
// routes and compute addresses for peers as connections are opened.
type SecureTransport struct {
	peerID     peer.ID
	host       host.Host
	psk        pnet.PSK
	protocolID protocol.ID
	key        wmcrypto.PrivateKey
	eps        []string
	iface      wireguard.Interface
}

// New is a standalone constructor for SecureTransport.
func New(id protocol.ID, host host.Host, psk pnet.PSK, privkey crypto.PrivKey) (*SecureTransport, error) {
	peerID, err := peer.IDFromPrivateKey(privkey)
	if err != nil {
		return nil, fmt.Errorf("failed to extract peer ID from private key: %w", err)
	}
	key, err := util.ToWebmeshPrivateKey(privkey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert private key to webmesh key: %w", err)
	}
	sec := &SecureTransport{
		peerID:     peerID,
		host:       host,
		psk:        psk,
		protocolID: id,
		key:        key,
	}
	ctx := context.Background()
	// Detect our public endpoints (libp2p probably has mechanisms for this already)
	eps, err := endpoints.Detect(ctx, endpoints.DetectOpts{
		DetectPrivate: true,
		DetectIPv6:    true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to detect local endpoints: %w", err)
	}
	// Determine what our local network will be.
	var ula netip.Prefix
	var addr netip.Addr
	if len(psk) > 0 {
		// We are going to seed the ULA with the PSK and use it for all connections.
		ula = netutil.GenerateULAWithSeed(psk)
		addr = netutil.AssignToPrefix(ula, key.PublicKey()).Addr()
	} else {
		// We'll generate our own unique local addresses.
		ula, addr = netutil.GenerateULAWithKey(key.PublicKey())
	}
	// We go ahead and create an interface for ourself. If we can't do this we'll fail to
	// do pretty much everything.
	wgopts := wireguard.Options{
		NodeID: host.ID().String(),
		// Will only work on Linux/Windows, needs to be utun+ on macOS.
		Name: func() string {
			if runtime.GOOS == "darwin" {
				return "utun9"
			}
			// Pick a random number to append to the interface name
			r := rand.New(rand.NewSource(time.Now().UnixNano()))
			return fmt.Sprintf("webmesh%d", r.Intn(1000))
		}(),
		ForceName:   true,
		MTU:         system.DefaultMTU,
		NetworkV6:   ula,
		AddressV6:   netip.PrefixFrom(addr, wmproto.PrefixSize),
		DisableIPv4: true,
	}
	iface, err := wireguard.New(ctx, &wgopts)
	if err != nil {
		return nil, fmt.Errorf("failed to create wireguard interface: %w", err)
	}
	err = iface.AddRoute(ctx, ula)
	if err != nil && !system.IsRouteExists(err) {
		return nil, fmt.Errorf("failed to add route: %w", err)
	}
	err = iface.Configure(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("failed to configure wireguard interface: %w", err)
	}
	sec.iface = iface
	lport, _ := iface.ListenPort()
	addrports := eps.AddrPorts(uint16(lport))
	for _, addrport := range addrports {
		sec.eps = append(sec.eps, addrport.String())
	}
	return sec, nil
}

// ID is the protocol ID of the security protocol.
func (st *SecureTransport) ID() protocol.ID { return st.protocolID }

// SecureInbound secures an inbound connection. If p is empty, connections from any peer are accepted.
func (st *SecureTransport) SecureInbound(ctx context.Context, insecure net.Conn, p peer.ID) (sec.SecureConn, error) {
	return st.secureConn(ctx, insecure, p, network.DirInbound)
}

// SecureOutbound secures an outbound connection.
func (st *SecureTransport) SecureOutbound(ctx context.Context, insecure net.Conn, p peer.ID) (sec.SecureConn, error) {
	return st.secureConn(ctx, insecure, p, network.DirOutbound)
}

func (st *SecureTransport) secureConn(ctx context.Context, insecure net.Conn, p peer.ID, dir network.Direction) (sec.SecureConn, error) {
	ic := insecure
	defer ic.Close()
	c, err := st.NewSecureConn(ctx, insecure.(mnet.Conn), p, st.psk, dir, st.iface)
	if err != nil {
		return nil, fmt.Errorf("failed to secure connection: %w", err)
	}
	return c, nil
}
