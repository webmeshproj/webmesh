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
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	"github.com/multiformats/go-multiaddr"
	"github.com/pion/webrtc/v3"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/net/transport"
)

// WebRTCExternalSignalOptions are options for configuring a WebRTC signaling transport.
type WebRTCExternalSignalOptions struct {
	// NodeID is the node ID to advertise to the peer. Contrary to other
	// uses of signaling, this is the node ID of the local node and not
	// the remote node. The remote node should be expecting this node ID
	// on the rendevous string.
	NodeID string
	// Rendevous is the rendevous string to use for the DHT.
	// The remote peer should be expecting NodeID on this rendevous string.
	Rendevous string
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
	SetBuffers(context.WithLogger(ctx, log))
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
		WebRTCExternalSignalOptions: opts,
		host:                        host,
		dht:                         kaddht,
		candidatec:                  make(chan webrtc.ICECandidateInit, 16),
		errorc:                      make(chan error, 1),
		cancel:                      func() {},
	}, nil
}

type externalSignalTransport struct {
	WebRTCExternalSignalOptions
	host              host.Host
	dht               *dht.IpfsDHT
	buf               *bufio.ReadWriter
	turnServers       []webrtc.ICEServer
	remoteDescription webrtc.SessionDescription
	candidatec        chan webrtc.ICECandidateInit
	errorc            chan error
	cancel            context.CancelFunc
	mu                sync.Mutex
}

// Start starts the transport.
func (rt *externalSignalTransport) Start(ctx context.Context) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	log := context.LoggerFrom(ctx).With("libp2p", "webrtc-signal")
	routingDiscovery := drouting.NewRoutingDiscovery(rt.dht)

StartSignaling:
	for {
		peerChan, err := routingDiscovery.FindPeers(ctx, rt.Rendevous)
		if err != nil {
			return fmt.Errorf("libp2p find peers: %w", err)
		}
		log.Debug("Waiting for peer to establish connection with")
		for {
			select {
			case <-ctx.Done():
				return fmt.Errorf("context canceled")
			case peer := <-peerChan:
				if peer.ID == rt.host.ID() || len(peer.Addrs) == 0 {
					continue
				}
				log := log.With(slog.String("peer-id", peer.ID.String()))
				// Try to connect to the peer.
				log.Debug("Connecting to peer")
				if rt.ConnectTimeout > 0 {
					ctx, rt.cancel = context.WithTimeout(ctx, rt.ConnectTimeout)
				} else {
					ctx, rt.cancel = context.WithCancel(ctx)
				}
				stream, err := rt.host.NewStream(ctx, peer.ID, WebRTCSignalProtocolFor(rt.Rendevous))
				if err != nil {
					log.Debug("Failed to connect to peer", "error", err.Error())
					continue
				}
				rt.buf = bufio.NewReadWriter(bufio.NewReader(stream), bufio.NewWriter(stream))
				// Send the target protocol and address to the peer.
				data, err := protojson.Marshal(&v1.StartDataChannelRequest{
					NodeId: rt.NodeID,
					Proto:  rt.TargetProto,
					Dst:    rt.TargetAddr.Addr().String(),
					Port:   uint32(rt.TargetAddr.Port()),
				})
				if err != nil {
					return fmt.Errorf("marshal start data channel request: %w", err)
				}
				log.Debug("Sending start data channel request")
				_, err = rt.buf.Write(append(data, '\r'))
				if err != nil {
					return fmt.Errorf("write start data channel request: %w", err)
				}
				err = rt.buf.Flush()
				if err != nil {
					return fmt.Errorf("flush start data channel request: %w", err)
				}
				// Read the next offer from the stream.
				log.Debug("Waiting for remote description")
				line, err := rt.buf.ReadString('\r')
				if err != nil {
					return fmt.Errorf("read remote description: %w", err)
				}
				// Unmarshal the line into a start data channel offer object.
				var msg v1.DataChannelOffer
				line = line[:len(line)-1]
				err = protojson.Unmarshal([]byte(line), &msg)
				if err != nil {
					return fmt.Errorf("unmarshal start data channel offer: %w", err)
				}
				var offer webrtc.SessionDescription
				err = json.Unmarshal([]byte(msg.GetOffer()), &offer)
				if err != nil {
					return fmt.Errorf("unmarshal SDP offer: %w", err)
				}
				log.Debug("Received remote description", "description", &offer)
				rt.remoteDescription = offer
				rt.turnServers = make([]webrtc.ICEServer, len(msg.GetStunServers()))
				for i, server := range msg.GetStunServers() {
					rt.turnServers[i] = webrtc.ICEServer{
						URLs: []string{server},
					}
				}
				go rt.handleStream(ctx, stream, rt.buf)
				break StartSignaling
			}
		}
	}
	return nil
}

// TURNServers returns a list of TURN servers configured for the transport.
func (rt *externalSignalTransport) TURNServers() []webrtc.ICEServer {
	return rt.turnServers
}

// SendDescription sends an SDP description to the remote peer.
func (rt *externalSignalTransport) SendDescription(ctx context.Context, desc webrtc.SessionDescription) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	log := context.LoggerFrom(ctx)
	log.Debug("Sending SDP description", "description", &desc)
	data, err := json.Marshal(desc)
	if err != nil {
		return fmt.Errorf("marshal SDP description: %w", err)
	}
	msg := &v1.StartDataChannelRequest{
		Answer: string(data),
	}
	data, err = protojson.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal start data channel request: %w", err)
	}
	_, err = rt.buf.Write(append(data, '\r'))
	if err != nil {
		return fmt.Errorf("write start data channel request: %w", err)
	}
	err = rt.buf.Flush()
	if err != nil {
		return fmt.Errorf("flush start data channel request: %w", err)
	}
	return nil
}

// SendCandidate sends an ICE candidate to the remote peer.
func (rt *externalSignalTransport) SendCandidate(ctx context.Context, candidate webrtc.ICECandidateInit) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	log := context.LoggerFrom(ctx)
	log.Debug("Sending ICE candidate", "candidate", &candidate)
	data, err := json.Marshal(candidate)
	if err != nil {
		return fmt.Errorf("marshal ICE candidate: %w", err)
	}
	msg := &v1.StartDataChannelRequest{
		Candidate: string(data),
	}
	data, err = protojson.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal start data channel request: %w", err)
	}
	_, err = rt.buf.Write(append(data, '\r'))
	if err != nil {
		return fmt.Errorf("write start data channel request: %w", err)
	}
	err = rt.buf.Flush()
	if err != nil {
		return fmt.Errorf("flush start data channel request: %w", err)
	}
	return nil
}

// Candidates returns a channel of ICE candidates received from the remote peer.
func (rt *externalSignalTransport) Candidates() <-chan webrtc.ICECandidateInit {
	return rt.candidatec
}

// RemoteDescription returns a channel the description received from the remote peer.
func (rt *externalSignalTransport) RemoteDescription() webrtc.SessionDescription {
	return rt.remoteDescription
}

// Error returns a channel that receives any error encountered during signaling.
// This channel will be closed when the transport is closed.
func (rt *externalSignalTransport) Error() <-chan error {
	return rt.errorc
}

// Close closes the transport.
func (rt *externalSignalTransport) Close() error {
	rt.cancel()
	defer rt.dht.Close()
	return rt.host.Close()
}

func (rt *externalSignalTransport) handleStream(ctx context.Context, stream network.Stream, buf *bufio.ReadWriter) {
	log := context.LoggerFrom(ctx)
	defer close(rt.errorc)
	defer stream.Close()
	for {
		// Read the next line from the stream.
		log.Debug("Waiting for next line")
		line, err := buf.ReadString('\r')
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			rt.errorc <- fmt.Errorf("read line: %w", err)
			return
		}
		// Unmarshal the line into a start data channel offer object.
		var msg v1.DataChannelOffer
		line = line[:len(line)-1]
		err = protojson.Unmarshal([]byte(line), &msg)
		if err != nil {
			rt.errorc <- fmt.Errorf("unmarshal start data channel offer: %w", err)
			return
		}
		if msg.GetCandidate() != "" {
			log.Debug("Received candidate message", "message", &msg)
			var candidate webrtc.ICECandidateInit
			err = json.Unmarshal([]byte(msg.GetCandidate()), &candidate)
			if err != nil {
				rt.errorc <- fmt.Errorf("unmarshal ICE candidate: %w", err)
				return
			}
			rt.candidatec <- candidate
		}
	}
}
