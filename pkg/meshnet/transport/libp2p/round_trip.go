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
	"errors"
	"fmt"

	"github.com/multiformats/go-multiaddr"
	v1 "github.com/webmeshproj/api/go/v1"
	"google.golang.org/grpc"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/meshnet/transport"
)

// RoundTripOptions are options for performing a round trip against a discovery node.
type RoundTripOptions struct {
	// Multiaddrs are the multiaddrs to dial. These are mutually exclusive with
	// Rendezvous.
	Multiaddrs []multiaddr.Multiaddr
	// Rendezvous is a rendezvous point on the DHT.
	Rendezvous string
	// HostOptions are options for configuring the host. These can be left
	// empty if using a pre-created host.
	HostOptions HostOptions
	// Method is the method to try to execute.
	Method string
	// Host is a pre-started host to use for the round trip
	Host Host
	// Credentials are gRPC DialOptions to use for the gRPC connection.
	Credentials []grpc.DialOption
}

// NewJoinRoundTripper returns a round tripper that dials the given multiaddrs directly
// using an uncertified peerstore.
func NewJoinRoundTripper(ctx context.Context, opts RoundTripOptions) (transport.JoinRoundTripper, error) {
	opts.Method = v1.Membership_Join_FullMethodName
	return NewRoundTripper[v1.JoinRequest, v1.JoinResponse](ctx, opts)
}

// NewDiscoveryJoinRoundTripper returns a round tripper that uses the libp2p kademlia DHT to join a cluster.
// The created host is closed when the round tripper is closed.
func NewDiscoveryJoinRoundTripper(ctx context.Context, opts RoundTripOptions) (transport.JoinRoundTripper, error) {
	opts.Method = v1.Membership_Join_FullMethodName
	return NewDiscoveryRoundTripper[v1.JoinRequest, v1.JoinResponse](ctx, opts)
}

// NewRoundTripper returns a round tripper that dials the given multiaddrs directly
// using an uncertified peerstore.
func NewRoundTripper[REQ, RESP any](ctx context.Context, opts RoundTripOptions) (transport.RoundTripper[REQ, RESP], error) {
	if opts.Method == "" {
		return nil, errors.New("method must be specified")
	}
	host := opts.Host
	close := func() {}
	if host == nil {
		var err error
		opts.HostOptions.UncertifiedPeerstore = true
		host, err = NewHost(ctx, opts.HostOptions)
		if err != nil {
			return nil, err
		}
		close = func() {
			err := host.Close()
			if err != nil {
				context.LoggerFrom(ctx).Error("Failed to close host", "error", err.Error())
			}
		}
	}
	return &roundTripper[REQ, RESP]{
		RoundTripOptions: opts,
		transport:        NewTransport(host, opts.Credentials...),
		close:            close,
	}, nil
}

// NewDiscoveryRoundTripper returns a round tripper that uses the libp2p kademlia DHT.
// The created host is closed when the round tripper is closed.
func NewDiscoveryRoundTripper[REQ, RESP any](ctx context.Context, opts RoundTripOptions) (transport.RoundTripper[REQ, RESP], error) {
	if opts.Method == "" {
		return nil, errors.New("method must be specified")
	}
	transport, err := NewDiscoveryTransport(ctx, TransportOptions{
		Rendezvous:  opts.Rendezvous,
		HostOptions: opts.HostOptions,
		Host:        opts.Host,
		Credentials: opts.Credentials,
	})
	if err != nil {
		return nil, fmt.Errorf("new discovery transport: %w", err)
	}
	return &discoveryRoundTripper[REQ, RESP]{
		RoundTripOptions: opts,
		transport:        transport,
		close: func() {
			err := transport.(*rpcDiscoveryTransport).Close()
			if err != nil {
				context.LoggerFrom(ctx).Error("Failed to close transport", "error", err.Error())
			}
		},
	}, nil
}

type roundTripper[REQ, RESP any] struct {
	RoundTripOptions
	transport transport.RPCTransport
	close     func()
}

func (rt *roundTripper[REQ, RESP]) RoundTrip(ctx context.Context, req *REQ) (*RESP, error) {
	log := context.LoggerFrom(ctx).With("method", rt.Method)
	ctx = context.WithLogger(ctx, log)
	for _, addr := range rt.Multiaddrs {
		log.Debug("Attempting to dial node via libp2p")
		conn, err := rt.transport.Dial(ctx, "", addr.String())
		if err != nil {
			log.Warn("Dial failed", "error", err.Error())
			continue
		}
		defer conn.Close()
		log.Debug("Dial successful, invoking request")
		var resp RESP
		var callOpts []grpc.CallOption
		for _, cred := range rt.Credentials {
			if callCred, ok := cred.(grpc.CallOption); ok {
				log.Debug("Adding call option", "option", callCred)
				callOpts = append(callOpts, callCred)
			}
		}
		err = conn.Invoke(ctx, rt.Method, req, &resp, callOpts...)
		if err != nil {
			log.Debug("Invoke request failed", "error", err)
			return nil, err
		}
		return &resp, nil
	}
	return nil, fmt.Errorf("no more addresses to dial")
}

func (rt *roundTripper[REQ, RESP]) Close() error {
	rt.close()
	return nil
}

type discoveryRoundTripper[REQ, RESP any] struct {
	RoundTripOptions
	transport transport.RPCTransport
	close     func()
}

func (rt *discoveryRoundTripper[REQ, RESP]) Close() error {
	rt.close()
	return nil
}

func (rt *discoveryRoundTripper[REQ, RESP]) RoundTrip(ctx context.Context, req *REQ) (*RESP, error) {
	log := context.LoggerFrom(ctx).With("method", rt.Method)
	ctx = context.WithLogger(ctx, log)
	log.Debug("Attempting to dial node via libp2p")
	conn, err := rt.transport.Dial(ctx, "", "")
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	log.Debug("Dial successful, invoking request")
	var resp RESP
	var callOpts []grpc.CallOption
	for _, cred := range rt.Credentials {
		if callCred, ok := cred.(grpc.CallOption); ok {
			log.Debug("Adding call option", "option", callCred)
			callOpts = append(callOpts, callCred)
		}
	}
	err = conn.Invoke(ctx, rt.Method, req, &resp, callOpts...)
	if err != nil {
		log.Debug("Invoke request failed", "error", err)
		return nil, err
	}
	return &resp, nil
}
