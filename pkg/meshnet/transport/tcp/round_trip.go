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

package tcp

import (
	"errors"
	"time"

	v1 "github.com/webmeshproj/api/go/v1"
	"google.golang.org/grpc"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/meshnet/transport"
)

// RoundTripOptions are options for a gRPC round tripper.
type RoundTripOptions struct {
	// Addrs is a list of addresses to try to join. The list will be iterated on
	// until a successful join occurs.
	Addrs []string
	// Credentials are the gRPC DialOptions to use for the gRPC connection.
	Credentials []grpc.DialOption
	// AddressTimeout is the timeout for dialing each address. If not set
	// any timeout on the context will be used.
	AddressTimeout time.Duration
}

// NewJoinRoundTripper creates a new gRPC round tripper for issuing a Join Request.
func NewJoinRoundTripper(opts RoundTripOptions) transport.JoinRoundTripper {
	return NewRoundTripper[v1.JoinRequest, v1.JoinResponse](opts, v1.Membership_Join_FullMethodName)
}

// NewRoundTripper creates a new gRPC round tripper for the given method.
func NewRoundTripper[REQ, RESP any](opts RoundTripOptions, method string) transport.RoundTripper[REQ, RESP] {
	return &grpcRoundTripper[REQ, RESP]{
		RoundTripOptions: opts,
		method:           method,
	}
}

type grpcRoundTripper[REQ, RESP any] struct {
	RoundTripOptions
	method string
}

func (rt *grpcRoundTripper[REQ, RESP]) Close() error { return nil }

func (rt *grpcRoundTripper[REQ, RESP]) RoundTrip(ctx context.Context, req *REQ) (*RESP, error) {
	var dialCtx context.Context
	var cancel context.CancelFunc
	var err error
	t := NewGRPCTransport(TransportOptions{Credentials: rt.Credentials})
	for _, addr := range rt.Addrs {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		log := context.LoggerFrom(ctx).With("join-addr", addr, "method", rt.method)
		log.Debug("Attempting to dial node")
		if rt.AddressTimeout > 0 {
			dialCtx, cancel = context.WithTimeout(ctx, rt.AddressTimeout)
		} else {
			dialCtx = ctx
		}
		var conn transport.RPCClientConn
		conn, err = t.Dial(dialCtx, "", addr)
		cancel()
		if err != nil {
			log.Debug("Failed to dial node", "error", err)
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
		err = conn.Invoke(ctx, rt.method, req, &resp, callOpts...)
		if err != nil {
			log.Debug("Invoke request failed", "error", err)
			continue
		}
		return &resp, nil
	}
	if err != nil {
		// Return the last error if we have one.
		return nil, err
	}
	// We should never get here.
	return nil, errors.New("no addresses to dial")
}
