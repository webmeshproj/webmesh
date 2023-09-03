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
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/net/transport"
)

// Announcer is an interface for nodes that can announce themselves to the
// network.
type Announcer interface {
	// AnnounceToDHT should announce the join protocol to the DHT,
	// such that it can be used by a libp2p transport.JoinRoundTripper.
	AnnounceToDHT(ctx context.Context, opts AnnounceOptions) error
	// LeaveDHT should remove the join protocol from the DHT for the
	// given rendezvous string.
	LeaveDHT(ctx context.Context, rendezvous string) error
}

// AnnounceOptions are options for announcing the host or discovering peers
// on the libp2p kademlia DHT.
type AnnounceOptions struct {
	// Rendezvous is the pre-shared key to use as a rendezvous point for the DHT.
	Rendezvous string
	// AnnounceTTL is the TTL to use for the discovery service.
	AnnounceTTL time.Duration
	// HostOptions are options for configuring the host. These can be left
	// empty if using a pre-created host.
	HostOptions HostOptions
	// Method is the method to announce.
	Method string
	// Host is a pre-started host to use for announcing.
	Host Host
	// Key is the host's private key. One will be generated if this is nil.
	Key crypto.Key
}

// NewAnnouncer creates a generic announcer for the given method, request, and response objects.
func NewAnnouncer[REQ, RESP any](ctx context.Context, opts AnnounceOptions, rt transport.UnaryServer[REQ, RESP]) (io.Closer, error) {
	host := opts.Host
	close := func() error { return nil }
	var err error
	if host == nil {
		if opts.Key == nil {
			opts.Key, err = crypto.GenerateKey()
			if err != nil {
				return nil, err
			}
		}
		host, err = NewHostWithKey(ctx, opts.HostOptions, opts.Key)
		if err != nil {
			return nil, err
		}
		close = func() error { return host.Close(ctx) }
	}
	return newAnnouncerWithHostAndCloseFunc[REQ, RESP](ctx, host, opts, rt, close), nil
}

// NewAnnouncerWithHost creates a generic announcer for the given method, request, and response objects.
func NewAnnouncerWithHost[REQ, RESP any](ctx context.Context, host Host, opts AnnounceOptions, rt transport.UnaryServer[REQ, RESP]) io.Closer {
	return newAnnouncerWithHostAndCloseFunc[REQ, RESP](ctx, host, opts, rt, func() error { return nil })
}

// NewJoinAnnouncer creates a new announcer on the kadmilia DHT and executes
// received join requests against the given join Server.
func NewJoinAnnouncer(ctx context.Context, opts AnnounceOptions, join transport.JoinServer) (io.Closer, error) {
	opts.Method = v1.Membership_Join_FullMethodName
	return NewAnnouncer(ctx, opts, join)
}

// NewJoinAnnouncerWithHost creates a new announcer on the kadmilia DHT and executes
// received join requests against the given join Server.
func NewJoinAnnouncerWithHost(ctx context.Context, host Host, opts AnnounceOptions, join transport.JoinServer) io.Closer {
	opts.Method = v1.Membership_Join_FullMethodName
	return NewAnnouncerWithHost(ctx, host, opts, join)
}

func newAnnouncerWithHostAndCloseFunc[REQ, RESP any](ctx context.Context, host Host, opts AnnounceOptions, rt transport.UnaryServer[REQ, RESP], close func() error) io.Closer {
	log := context.LoggerFrom(ctx).With(slog.String("host-id", host.ID().String()))
	host.Host().SetStreamHandler(RPCProtocolFor(opts.Method), func(s network.Stream) {
		log.Debug("Handling join protocol stream", "peer", s.Conn().RemotePeer())
		go handleIncomingStream(log, rt, s)
	})
	log.Debug("Announcing join protocol with our PSK")
	routingDiscovery := drouting.NewRoutingDiscovery(host.DHT())
	var discoveryOpts []discovery.Option
	if opts.AnnounceTTL > 0 {
		discoveryOpts = append(discoveryOpts, discovery.TTL(opts.AnnounceTTL))
	}
	advertise, cancel := context.WithCancel(context.Background())
	dutil.Advertise(advertise, routingDiscovery, opts.Rendezvous, discoveryOpts...)
	announcer := &announcer[REQ, RESP]{
		close: func() error {
			cancel()
			return close()
		},
	}
	return announcer
}

type announcer[REQ, RESP any] struct {
	close func() error
}

func (srv *announcer[REQ, RESP]) Close() error {
	return srv.close()
}

func handleIncomingStream[REQ, RESP any](log *slog.Logger, server transport.UnaryServer[REQ, RESP], conn network.Stream) {
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
	var req REQ
	err = proto.Unmarshal(buf, any(&req).(proto.Message))
	if err != nil {
		rlog.Error("Failed to unmarshal join request from peer", slog.String("error", err.Error()))
		returnErr(conn, err)
		return
	}
	// Execute the join request
	rlog.Debug("Executing join request")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15) // TODO: Make this configurable
	defer cancel()
	resp, err := server.Serve(context.WithLogger(ctx, rlog), &req)
	if err != nil {
		rlog.Error("Failed to execute join request", slog.String("error", err.Error()))
		returnErr(conn, err)
		return
	}
	// Write the response back to the peer
	buf, err = proto.Marshal(any(resp).(proto.Message))
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
