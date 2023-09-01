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
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/config"
	"github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	dutil "github.com/libp2p/go-libp2p/p2p/discovery/util"
	"github.com/multiformats/go-multiaddr"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/net/transport/datachannels"
)

// DataChannelAnnounceOptions are options for announcing webrtc signaling
// for data channels to remote peers.
type DataChannelAnnounceOptions struct {
	// RendevousStrings is a map of peer IDs to rendezvous strings
	// for allowing signaling through libp2p.
	RendezvousStrings map[string]string
	// BootstrapPeers is a list of bootstrap peers to use for the DHT.
	// If empty or nil, the default bootstrap peers will be used.
	BootstrapPeers []multiaddr.Multiaddr
	// Options are options for configuring the libp2p host.
	Options []config.Option
	// AnnounceTTL is the TTL for each announcement.
	AnnounceTTL time.Duration
	// LocalAddrs is a list of local addresses to announce the host with.
	// If empty or nil, the default local addresses will be used.
	LocalAddrs []multiaddr.Multiaddr
	// STUNServers is a list of STUN servers to use for NAT traversal.
	// If empty, the default STUN servers will be used.
	STUNServers []string
	// DataChannelTimeout is the timeout for starting data channel connections.
	DataChannelTimeout time.Duration
	// WireGuardPort is the port to use for WireGuard connections.
	WireGuardPort int
	// ConnectTimeout is the timeout for connecting to peers.
	ConnectTimeout time.Duration
}

// NewDataChannelAnnouncer creates a new announcer on the kadmilia DHT and executes
// received signaling requests against the local node.
func NewDataChannelAnnouncer(ctx context.Context, opts DataChannelAnnounceOptions) (*DataChannelAnnouncer, error) {
	var err error
	log := context.LoggerFrom(ctx)
	SetBuffers(ctx)
	announcer := &DataChannelAnnouncer{
		opts:   opts,
		closec: make(chan struct{}),
	}
	if len(opts.LocalAddrs) > 0 {
		opts.Options = append(opts.Options, libp2p.ListenAddrs(opts.LocalAddrs...))
	}
	announcer.host, err = libp2p.New(opts.Options...)
	if err != nil {
		return nil, fmt.Errorf("libp2p new host: %w", err)
	}
	announcer.host.SetStreamHandler(JoinProtocol, func(s network.Stream) {
		log.Debug("Handling data channel protocol stream", "peer", s.Conn().RemotePeer())
		go announcer.handleStream(context.WithLogger(context.Background(), log), s)
	})
	log = log.With(slog.String("host-id", announcer.host.ID().String()))
	ctx = context.WithLogger(ctx, log)
	// Bootstrap the DHT.
	log.Debug("Bootstrapping DHT")
	announcer.dht, err = NewDHT(ctx, announcer.host, opts.BootstrapPeers, opts.ConnectTimeout)
	if err != nil {
		defer announcer.host.Close()
		return nil, fmt.Errorf("libp2p new dht: %w", err)
	}
	// Announce the join protocol with our PSK.
	log.Debug("Announcing data channel protocol with our PSK")
	routingDiscovery := drouting.NewRoutingDiscovery(announcer.dht)
	var discoveryOpts []discovery.Option
	if opts.AnnounceTTL > 0 {
		discoveryOpts = append(discoveryOpts, discovery.TTL(opts.AnnounceTTL))
	}
	for _, rendezvous := range opts.RendezvousStrings {
		dutil.Advertise(ctx, routingDiscovery, rendezvous, discoveryOpts...)
	}
	return announcer, nil
}

type DataChannelAnnouncer struct {
	opts   DataChannelAnnounceOptions
	dht    *dht.IpfsDHT
	host   host.Host
	closec chan struct{}
}

// Close closes the announcer.
func (a *DataChannelAnnouncer) Close() error {
	defer close(a.closec)
	defer a.host.Close()
	return a.dht.Close()
}

func (a *DataChannelAnnouncer) handleStream(ctx context.Context, stream network.Stream) {
	log := context.LoggerFrom(ctx)
	defer stream.Close()
	log.Debug("Handling data channel protocol stream", "peer", stream.Conn().RemotePeer())
	// Determine the rendevous point the peer used.
	rendevous := WebRTCRendevousFrom(stream.Protocol())
	if rendevous == "" {
		log.Warn("Received data channel protocol stream without rendezvous")
		return
	}
	// Pull the peer ID from our internal map.
	expectedPeer := a.opts.RendezvousStrings[rendevous]
	if expectedPeer == "" {
		log.Warn("Received data channel protocol stream with unknown rendezvous", "rendevous", rendevous)
		return
	}
	// Create a buffer for the stream
	buf := bufio.NewReadWriter(bufio.NewReader(stream), bufio.NewWriter(stream))
	// Pull the initial request from the stream.
	data, err := buf.ReadBytes('\r')
	if err != nil {
		log.Warn("Failed to read initial request", "err", err)
		return
	}
	// Parse the request.
	data = data[:len(data)-1]
	var req v1.StartDataChannelRequest
	if err := protojson.Unmarshal(data, &req); err != nil {
		log.Warn("Failed to unmarshal initial request", "err", err)
		return
	}
	// Check the peer ID.
	if req.GetNodeId() != expectedPeer {
		log.Warn("Received data channel protocol stream with unexpected peer ID", "expected", expectedPeer, "actual", req.GetNodeId())
		return
	}
	// Start the requested data channel.
	a.handleRequest(ctx, stream, &req)
}

func (a *DataChannelAnnouncer) handleRequest(ctx context.Context, stream network.Stream, req *v1.StartDataChannelRequest) {
	log := context.LoggerFrom(ctx)
	log.Debug("Handling data channel protocol request", "peer", stream.Conn().RemotePeer(), "request", req)
	var conn datachannels.ManagedServerChannel
	var err error
	if req.GetProto() == "udp" && req.GetPort() == 0 {
		log.Info("Negotiating WireGuard proxy connection")
		conn, err = datachannels.NewWireGuardProxyServer(ctx, a.opts.STUNServers, uint16(a.opts.WireGuardPort))
	} else {
		log.Info("Negotiating standard WebRTC connection")
		conn, err = datachannels.NewPeerConnectionServer(ctx, &datachannels.OfferOptions{
			Proto:       req.GetProto(),
			SrcAddress:  stream.Conn().RemoteMultiaddr().String(),
			DstAddress:  net.JoinHostPort(req.GetDst(), strconv.Itoa(int(req.GetPort()))),
			STUNServers: a.opts.STUNServers,
		})
	}
	if err != nil {
		log.Error("Failed to negotiate data channel connection", "error", err.Error())
		return
	}
	go func() {
		<-conn.Closed()
		log.Info("WebRTC connection closed")
	}()
	log.Debug("Sending offer to client", slog.String("offer", conn.Offer()))
	buf := bufio.NewReadWriter(bufio.NewReader(stream), bufio.NewWriter(stream))
	offer := v1.DataChannelOffer{
		Offer:       conn.Offer(),
		StunServers: a.opts.STUNServers,
	}
	data, err := protojson.Marshal(&offer)
	if err != nil {
		defer conn.Close()
		log.Error("Failed to marshal offer", "error", err.Error())
		return
	}
	if _, err := buf.Write(append(data, '\r')); err != nil {
		defer conn.Close()
		log.Error("Failed to write offer", "error", err.Error())
		return
	}
	if err := buf.Flush(); err != nil {
		defer conn.Close()
		log.Error("Failed to flush offer", "error", err.Error())
		return
	}
	// Wait for the answer.
	log.Debug("Waiting for answer")
	data, err = buf.ReadBytes('\r')
	if err != nil {
		defer conn.Close()
		log.Error("Failed to read answer", "error", err.Error())
		return
	}
	data = data[:len(data)-1]
	var resp v1.DataChannelNegotiation
	if err := protojson.Unmarshal(data, &resp); err != nil {
		defer conn.Close()
		log.Error("Failed to unmarshal answer", "error", err.Error())
		return
	}
	log.Debug("Answering offer from other node", slog.String("answer", resp.GetAnswer()))
	err = conn.AnswerOffer(resp.GetAnswer())
	if err != nil {
		defer conn.Close()
		log.Error("Failed to answer offer", "error", err.Error())
		return
	}
	// Handle candidate negotiation
	go func() {
		for candidate := range conn.Candidates() {
			if candidate == "" {
				continue
			}
			log.Debug("Sending ICE candidate", slog.String("candidate", candidate))
			msg := v1.DataChannelNegotiation{
				Candidate: candidate,
			}
			data, err := protojson.Marshal(&msg)
			if err != nil {
				log.Error("error sending ICE candidate", slog.String("error", err.Error()))
				return
			}
			_, err = buf.Write(append(data, '\r'))
			if err != nil {
				log.Error("error sending ICE candidate", slog.String("error", err.Error()))
				return
			}
		}
	}()
	for {
		data, err := buf.ReadBytes('\r')
		if err != nil {
			log.Error("error reading ICE candidate", slog.String("error", err.Error()))
			return
		}
		data = data[:len(data)-1]
		var msg v1.DataChannelNegotiation
		if err := protojson.Unmarshal(data, &msg); err != nil {
			log.Error("error reading ICE candidate", slog.String("error", err.Error()))
			return
		}
		if msg.GetCandidate() == "" {
			continue
		}
		log.Debug("Received ICE candidate", slog.String("candidate", msg.GetCandidate()))
		err = conn.AddCandidate(msg.GetCandidate())
		if err != nil {
			log.Error("Error adding ICE candidate", slog.String("error", err.Error()))
			return
		}
	}
}
