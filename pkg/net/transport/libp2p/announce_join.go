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
	"io"
	"log/slog"
	"time"

	"github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/network"
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	dutil "github.com/libp2p/go-libp2p/p2p/discovery/util"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/proto"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/net/transport"
)

// JoinAnnounceOptions are options for announcing the host or discovering peers
// on the libp2p kademlia DHT.
type JoinAnnounceOptions struct {
	// PSK is the pre-shared key to use as a rendezvous point for the DHT.
	PSK string
	// AnnounceTTL is the TTL to use for the discovery service.
	AnnounceTTL time.Duration
	// Host are options for configuring the host. These can be left
	// empty if using a pre-created host.
	Host HostOptions
}

// NewJoinAnnouncer creates a new announcer on the kadmilia DHT and executes
// received join requests against the given join Server.
func NewJoinAnnouncer(ctx context.Context, opts JoinAnnounceOptions, join transport.JoinServer) (io.Closer, error) {
	host, err := NewHost(ctx, opts.Host)
	if err != nil {
		return nil, err
	}
	log := context.LoggerFrom(ctx).With(slog.String("host-id", host.ID().String()))
	host.Host().SetStreamHandler(JoinProtocol, func(s network.Stream) {
		log.Debug("Handling join protocol stream", "peer", s.Conn().RemotePeer())
		go handleIncomingStream(log, join, s)
	})
	log.Debug("Announcing join protocol with our PSK")
	routingDiscovery := drouting.NewRoutingDiscovery(host.DHT())
	var discoveryOpts []discovery.Option
	if opts.AnnounceTTL > 0 {
		discoveryOpts = append(discoveryOpts, discovery.TTL(opts.AnnounceTTL))
	}
	dutil.Advertise(context.Background(), routingDiscovery, opts.PSK, discoveryOpts...)
	announcer := &dhtJoinAnnouncer{
		close: func() error {
			return host.Close(context.Background())
		},
	}
	return announcer, nil
}

// NewJoinAnnouncerWithHost creates a new announcer on the kadmilia DHT and executes
// received join requests against the given join Server.
func NewJoinAnnouncerWithHost(ctx context.Context, host Host, opts JoinAnnounceOptions, join transport.JoinServer) io.Closer {
	log := context.LoggerFrom(ctx).With(slog.String("host-id", host.Host().ID().String()))
	host.Host().SetStreamHandler(JoinProtocol, func(s network.Stream) {
		log.Debug("Handling join protocol stream", "peer", s.Conn().RemotePeer())
		go handleIncomingStream(log, join, s)
	})
	log.Debug("Announcing join protocol with our PSK")
	routingDiscovery := drouting.NewRoutingDiscovery(host.DHT())
	var discoveryOpts []discovery.Option
	if opts.AnnounceTTL > 0 {
		discoveryOpts = append(discoveryOpts, discovery.TTL(opts.AnnounceTTL))
	}
	dutil.Advertise(context.Background(), routingDiscovery, opts.PSK, discoveryOpts...)
	announcer := &dhtJoinAnnouncer{
		close: func() error {
			host.Host().RemoveStreamHandler(JoinProtocol)
			return nil
		},
	}
	return announcer
}

type dhtJoinAnnouncer struct {
	close func() error
}

func handleIncomingStream(log *slog.Logger, joinServer transport.JoinServer, conn network.Stream) {
	returnErr := func(stream network.Stream, err error) {
		log.Error("Failed to handle join protocol stream", slog.String("error", err.Error()))
		buf := []byte("ERROR: " + err.Error())
		if _, err := stream.Write(buf); err != nil {
			log.Error("Failed to write error to peer", slog.String("error", err.Error()))
		}
	}
	rlog := log.With(slog.String("peer-id", conn.Conn().RemotePeer().String()))
	rlog.Debug("Handling join protocol stream")
	defer conn.Close()
	// Read a join request off the wire
	var b [8192]byte
	n, err := conn.Read(b[:])
	if err != nil {
		rlog.Error("Failed to read join request from peer", slog.String("error", err.Error()))
		returnErr(conn, err)
		return
	}
	buf := b[:n]
	var req v1.JoinRequest
	err = proto.Unmarshal(buf, &req)
	if err != nil {
		rlog.Error("Failed to unmarshal join request from peer", slog.String("error", err.Error()))
		returnErr(conn, err)
		return
	}
	// Execute the join request
	rlog.Debug("Executing join request")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15) // TODO: Make this configurable
	defer cancel()
	resp, err := joinServer.Serve(context.WithLogger(ctx, rlog), &req)
	if err != nil {
		rlog.Error("Failed to execute join request", slog.String("error", err.Error()))
		returnErr(conn, err)
		return
	}
	// Write the response back to the peer
	buf, err = proto.Marshal(resp)
	if err != nil {
		rlog.Error("Failed to marshal join response", slog.String("error", err.Error()))
		returnErr(conn, err)
		return
	}
	if _, err := conn.Write(buf); err != nil {
		rlog.Error("Failed to write join response to peer", slog.String("error", err.Error()))
		return
	}
}

func (srv *dhtJoinAnnouncer) Close() error {
	return srv.close()
}
