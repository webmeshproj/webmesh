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

	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/proto"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/net/transport"
)

// RoundTripOptions are options for performing a round trip against
// a libp2p host.
type RoundTripOptions struct {
	// PSK is the pre-shared key to use as a rendezvous point for the DHT.
	PSK string
	// Host are options for configuring the host. These can be left
	// empty if using a pre-created host.
	Host HostOptions
}

// NewRoundTripper returns a round tripper that uses the libp2p kademlia DHT.
// The created host is closed when the round tripper is closed.
func NewRoundTripper[REQ, RESP any](opts RoundTripOptions, method string) transport.RoundTripper[REQ, RESP] {
	return &dhtRoundTripper[REQ, RESP]{RoundTripOptions: opts, method: method}
}

// NewRoundTripper returns a round tripper that uses the libp2p kademlia DHT.
func NewRoundTripperWithHost[REQ, RESP any](host Host, opts RoundTripOptions, method string) transport.RoundTripper[REQ, RESP] {
	return &dhtRoundTripperWithHost[REQ, RESP]{RoundTripOptions: opts, host: host, method: method}
}

// NewJoinRoundTripper returns a round tripper that uses the libp2p kademlia DHT to join a cluster.
// The created host is closed when the round tripper is closed.
func NewJoinRoundTripper(opts RoundTripOptions) transport.JoinRoundTripper {
	return &dhtRoundTripper[v1.JoinRequest, v1.JoinResponse]{
		RoundTripOptions: opts,
		method:           v1.Membership_Join_FullMethodName,
	}
}

// NewJoinRoundTripperHost returns a round tripper that uses the libp2p kademlia DHT to join a cluster.
func NewJoinRoundTripperWithHost(host Host, opts RoundTripOptions) transport.JoinRoundTripper {
	return &dhtRoundTripperWithHost[v1.JoinRequest, v1.JoinResponse]{
		RoundTripOptions: opts,
		method:           v1.Membership_Join_FullMethodName,
	}
}

type dhtRoundTripperWithHost[REQ, RESP any] struct {
	RoundTripOptions
	host   Host
	method string
}

func (rt *dhtRoundTripperWithHost[REQ, RESP]) RoundTrip(ctx context.Context, req *REQ) (*RESP, error) {
	log := context.LoggerFrom(ctx).With("method", rt.method)
	log = log.With(slog.String("host-id", rt.host.ID().String()))
	ctx = context.WithLogger(ctx, log)
	log.Debug("Searching for peers on the DHT with our PSK")
	routingDiscovery := drouting.NewRoutingDiscovery(rt.host.DHT())
	peerChan, err := routingDiscovery.FindPeers(ctx, rt.PSK)
	if err != nil {
		return nil, fmt.Errorf("libp2p find peers: %w", err)
	}
	// Marshal the join request
	joinData, err := proto.Marshal(any(req).(proto.Message))
	if err != nil {
		return nil, fmt.Errorf("marshal join request: %w", err)
	}
	// Wait for a peer to connect to
	log.Debug("Waiting for peer to establish connection with")
	for peer := range peerChan {
		// Ignore ourselves and hosts with no addresses.
		jlog := log.With(slog.String("peer-id", peer.ID.String()), slog.Any("peer-addrs", peer.Addrs))
		if peer.ID == rt.host.ID() || len(peer.Addrs) == 0 {
			jlog.Debug("Ignoring peer")
			continue
		}
		jlog.Debug("Dialing peer")
		var joinCtx context.Context
		var cancel context.CancelFunc
		if rt.Host.ConnectTimeout > 0 {
			joinCtx, cancel = context.WithTimeout(ctx, rt.Host.ConnectTimeout)
		} else {
			joinCtx, cancel = context.WithCancel(ctx)
		}
		stream, err := rt.host.Host().NewStream(joinCtx, peer.ID, JoinProtocol)
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
		_, err = stream.Write(joinData)
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
	return nil, errors.New("no peers found to dial")
}

type dhtRoundTripper[REQ, RESP any] struct {
	RoundTripOptions
	method string
}

func (rt *dhtRoundTripper[REQ, RESP]) RoundTrip(ctx context.Context, req *REQ) (*RESP, error) {
	log := context.LoggerFrom(ctx).With("method", rt.method)
	host, err := NewHost(ctx, rt.Host)
	if err != nil {
		return nil, err
	}
	defer host.Close(context.WithLogger(context.Background(), log))
	log = log.With(slog.String("host-id", host.ID().String()))
	ctx = context.WithLogger(ctx, log)
	log.Debug("Searching for peers on the DHT with our PSK")
	routingDiscovery := drouting.NewRoutingDiscovery(host.DHT())
	peerChan, err := routingDiscovery.FindPeers(ctx, rt.PSK)
	if err != nil {
		return nil, fmt.Errorf("libp2p find peers: %w", err)
	}
	// Marshal the join request
	joinData, err := proto.Marshal(any(req).(proto.Message))
	if err != nil {
		return nil, fmt.Errorf("marshal join request: %w", err)
	}
	// Wait for a peer to connect to
	log.Debug("Waiting for peer to establish connection with")
	for peer := range peerChan {
		// Ignore ourselves and hosts with no addresses.
		jlog := log.With(slog.String("peer-id", peer.ID.String()), slog.Any("peer-addrs", peer.Addrs))
		if peer.ID == host.ID() || len(peer.Addrs) == 0 {
			jlog.Debug("Ignoring peer")
			continue
		}
		jlog.Debug("Dialing peer")
		var joinCtx context.Context
		var cancel context.CancelFunc
		if rt.Host.ConnectTimeout > 0 {
			joinCtx, cancel = context.WithTimeout(ctx, rt.Host.ConnectTimeout)
		} else {
			joinCtx, cancel = context.WithCancel(ctx)
		}
		stream, err := host.Host().NewStream(joinCtx, peer.ID, JoinProtocol)
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
		_, err = stream.Write(joinData)
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
	return nil, errors.New("no peers found to dial")
}
