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
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/libp2p/go-libp2p/core/host"
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/proto"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/net/transport"
)

// RoundTripOptions are options for performing a round trip against
// a libp2p host.
type RoundTripOptions struct {
	// Rendezvous is the pre-shared key to use as a rendezvous point for the DHT.
	Rendezvous string
	// HostOptions are options for configuring the host. These can be left
	// empty if using a pre-created host.
	HostOptions HostOptions
	// Method is the method to try to execute.
	Method string
	// Host is a pre-started host to use for the round trip
	Host host.Host
}

// NewRoundTripper returns a round tripper that uses the libp2p kademlia DHT.
// The created host is closed when the round tripper is closed.
func NewRoundTripper[REQ, RESP any](ctx context.Context, opts RoundTripOptions) (transport.RoundTripper[REQ, RESP], error) {
	if opts.Method == "" {
		return nil, errors.New("method must be specified")
	}
	var h Host
	var err error
	var close func()
	if opts.Host != nil {
		dht, err := NewDHT(ctx, opts.Host, opts.HostOptions.BootstrapPeers, opts.HostOptions.ConnectTimeout)
		if err != nil {
			return nil, err
		}
		h = &libp2pHost{
			host: opts.Host,
			dht:  dht,
			opts: opts.HostOptions,
		}
		close = func() {
			err := dht.Close()
			if err != nil {
				context.LoggerFrom(ctx).Error("Failed to close DHT", "error", err.Error())
			}
		}
	} else {
		h, err = NewHostAndDHT(ctx, opts.HostOptions)
		if err != nil {
			return nil, err
		}
		close = func() {
			err := h.Close(ctx)
			if err != nil {
				context.LoggerFrom(ctx).Error("Failed to close host", "error", err.Error())
			}
		}
	}
	return newRoundTripperWithHostAndCloseFunc[REQ, RESP](h, opts, close), nil
}

// NewJoinRoundTripper returns a round tripper that uses the libp2p kademlia DHT to join a cluster.
// The created host is closed when the round tripper is closed.
func NewJoinRoundTripper(ctx context.Context, opts RoundTripOptions) (transport.JoinRoundTripper, error) {
	opts.Method = v1.Membership_Join_FullMethodName
	return NewRoundTripper[v1.JoinRequest, v1.JoinResponse](ctx, opts)
}

func newRoundTripperWithHostAndCloseFunc[REQ, RESP any](host Host, opts RoundTripOptions, close func()) transport.RoundTripper[REQ, RESP] {
	return &roundTripper[REQ, RESP]{RoundTripOptions: opts, host: host, close: close}
}

type roundTripper[REQ, RESP any] struct {
	RoundTripOptions
	host  Host
	close func()
}

func (rt *roundTripper[REQ, RESP]) Close() error {
	rt.close()
	return nil
}

func (rt *roundTripper[REQ, RESP]) RoundTrip(ctx context.Context, req *REQ) (*RESP, error) {
	log := context.LoggerFrom(ctx).With("method", rt.RoundTripOptions.Method)
	log = log.With(slog.String("host-id", rt.host.ID().String()))
	ctx = context.WithLogger(ctx, log)
	log.Debug("Searching for peers on the DHT with our PSK")
	routingDiscovery := drouting.NewRoutingDiscovery(rt.host.DHT())
	peerChan, err := routingDiscovery.FindPeers(ctx, rt.Rendezvous)
	if err != nil {
		return nil, fmt.Errorf("libp2p find peers: %w", err)
	}
	// Marshal the join request
	requestData, err := proto.Marshal(any(req).(proto.Message))
	if err != nil {
		return nil, fmt.Errorf("marshal join request: %w", err)
	}
	// Wait for a peer to connect to
	log.Debug("Waiting for peer to establish connection with")
SearchPeers:
	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("no peers found to dial: %w", ctx.Err())
		case peer, ok := <-peerChan:
			if !ok {
				if ctx.Err() != nil {
					return nil, fmt.Errorf("no peers found to dial: %w", ctx.Err())
				}
				continue SearchPeers
			}
			// Ignore ourselves and hosts with no addresses.
			jlog := log.With(slog.String("peer-id", peer.ID.String()), slog.Any("peer-addrs", peer.Addrs))
			if peer.ID == rt.host.ID() || len(peer.Addrs) == 0 {
				jlog.Debug("Ignoring peer")
				continue
			}
			jlog.Debug("Dialing peer")
			var connCtx context.Context
			var cancel context.CancelFunc
			if rt.HostOptions.ConnectTimeout > 0 {
				connCtx, cancel = context.WithTimeout(ctx, rt.HostOptions.ConnectTimeout)
			} else {
				connCtx, cancel = context.WithCancel(ctx)
			}
			stream, err := rt.host.Host().NewStream(connCtx, peer.ID, RPCProtocolFor(rt.RoundTripOptions.Method))
			cancel()
			if err != nil {
				// We'll try again with the next peer.
				jlog.Warn("Failed to connect to peer", slog.String("error", err.Error()))
				continue
			}
			jlog.Debug("Connected to peer")
			defer stream.Close()
			// Send a join request to the peer over the stream.
			jlog.Debug("Sending request to peer")
			_, err = stream.Write(requestData)
			if err != nil {
				return nil, fmt.Errorf("write request: %w", err)
			}
			var b [8192]byte
			n, err := stream.Read(b[:])
			if err != nil {
				if errors.Is(err, io.EOF) && n == 0 {
					return nil, fmt.Errorf("read response: %w", err)
				} else if !errors.Is(err, io.EOF) {
					return nil, fmt.Errorf("read response: %w", err)
				}
			}
			jlog.Debug("Received response from peer")
			if bytes.HasPrefix(b[:n], []byte("ERROR: ")) {
				return nil, fmt.Errorf("error from remote: %s", string(bytes.TrimPrefix(b[:n], []byte("ERROR: "))))
			}
			var resp RESP
			err = proto.Unmarshal(b[:n], any(&resp).(proto.Message))
			if err != nil {
				return nil, fmt.Errorf("unmarshal response: %w", err)
			}
			return &resp, nil
		}
	}
}
