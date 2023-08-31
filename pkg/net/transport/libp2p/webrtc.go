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
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/multiformats/go-multiaddr"
	"github.com/pion/webrtc/v3"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/net/system/buffers"
	"github.com/webmeshproj/webmesh/pkg/net/transport"
)

// WebRTCExternalSignalOptions are options for configuring a WebRTC signaling transport.
type WebRTCExternalSignalOptions struct {
	// Rendevous is the rendevous string to use for the DHT.
	PSK string
	// BootstrapPeers is a list of bootstrap peers to use for the DHT.
	// If empty or nil, the default bootstrap peers will be used.
	BootstrapPeers []multiaddr.Multiaddr
	// Options are options for configuring the libp2p host.
	Options []libp2p.Option
	// ConnectTimeout is the per-address timeout for connecting to a peer.
	ConnectTimeout time.Duration
	// LocalAddrs is a list of local addresses to listen on.
	// If empty or nil, the default local addresses will be used.
	LocalAddrs []multiaddr.Multiaddr
	// TargetProto is the target protocol to request from the remote node.
	TargetProto string
	// TargetAddr is the target address to request from the remote node.
	TargetAddr netip.AddrPort
}

// NewExternalSignalTransport returns a new WebRTC signaling transport that attempts
// to negotiate a WebRTC connection using the Webmesh WebRTC signaling server. This is
// typically used by clients trying to create a proxy connection to a server.
func NewExternalSignalTransport(ctx context.Context, opts WebRTCExternalSignalOptions) (transport.WebRTCSignalTransport, error) {
	log := context.LoggerFrom(ctx).With("libp2p", "webrtc-signal")
	// Try to set the maximum read and write buffer sizes.
	err := buffers.SetMaximumReadBuffer(2500000)
	if err != nil {
		log.Warn("Failed to set maximum read buffer", "error", err.Error())
	}
	err = buffers.SetMaximumWriteBuffer(2500000)
	if err != nil {
		log.Warn("Failed to set maximum write buffer", "error", err.Error())
	}
	// Create a new libp2p host.
	if len(opts.LocalAddrs) > 0 {
		opts.Options = append(opts.Options, libp2p.ListenAddrs(opts.LocalAddrs...))
	}
	host, err := libp2p.New(opts.Options...)
	if err != nil {
		return nil, fmt.Errorf("libp2p new host: %w", err)
	}
	log = log.With(slog.String("host-id", host.ID().String()))
	// Bootstrap the DHT.
	log.Debug("Bootstrapping DHT")
	kaddht, err := dht.New(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("libp2p new dht: %w", err)
	}
	err = bootstrapDHT(context.WithLogger(ctx, log), host, kaddht, opts.BootstrapPeers)
	if err != nil {
		defer host.Close()
		defer kaddht.Close()
		return nil, fmt.Errorf("libp2p bootstrap dht: %w", err)
	}
	return &externalSignalTransport{
		host:         host,
		dht:          kaddht,
		descriptionc: make(chan webrtc.SessionDescription, 1),
		candidatec:   make(chan webrtc.ICECandidateInit, 16),
		errorc:       make(chan error, 1),
	}, nil
}

type externalSignalTransport struct {
	host         host.Host
	dht          *dht.IpfsDHT
	turnServers  []webrtc.ICEServer
	descriptionc chan webrtc.SessionDescription
	candidatec   chan webrtc.ICECandidateInit
	errorc       chan error
}

// Start starts the transport.
func (ext *externalSignalTransport) Start(ctx context.Context) error {
	return nil
}

// TURNServers returns a list of TURN servers configured for the transport.
func (ext *externalSignalTransport) TURNServers() []webrtc.ICEServer {
	return ext.turnServers
}

// SendDescription sends an SDP description to the remote peer.
func (ext *externalSignalTransport) SendDescription(ctx context.Context, desc webrtc.SessionDescription) error {
	return nil
}

// SendCandidate sends an ICE candidate to the remote peer.
func (ext *externalSignalTransport) SendCandidate(ctx context.Context, candidate webrtc.ICECandidateInit) error {
	return nil
}

// Candidates returns a channel of ICE candidates received from the remote peer.
func (ext *externalSignalTransport) Candidates() <-chan webrtc.ICECandidateInit {
	return ext.candidatec
}

// Descriptions returns a channel of SDP descriptions received from the remote peer.
func (ext *externalSignalTransport) Descriptions() <-chan webrtc.SessionDescription {
	return ext.descriptionc
}

// Error returns a channel that receives any error encountered during signaling.
// This channel will be closed when the transport is closed.
func (ext *externalSignalTransport) Error() <-chan error {
	return ext.errorc
}

// Close closes the transport.
func (ext *externalSignalTransport) Close() error {
	defer ext.dht.Close()
	return ext.host.Close()
}
