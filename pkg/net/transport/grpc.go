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

package transport

import (
	"errors"
	"time"

	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc"

	"github.com/webmeshproj/webmesh/pkg/context"
)

// GRPCJoinOptions are options for the gRPC join round tripper.
type GRPCJoinOptions struct {
	// Addrs is a list of addresses to try to join. The list will be iterated on
	// until a successful join occurs.
	Addrs []string
	// Credentials are tge gRPC DialOptions to use for the gRPC connection.
	Credentials []grpc.DialOption
	// AddressTimeout is the timeout for dialing each address. If not set
	// any timeout on the context will be used.
	AddressTimeout time.Duration
}

// NewGRPCJoinRoundTripper creates a new gRPC join round tripper.
func NewGRPCJoinRoundTripper(opts GRPCJoinOptions) JoinRoundTripper {
	return &grpcJoinRoundTripper{opts}
}

type grpcJoinRoundTripper struct {
	GRPCJoinOptions
}

func (rt *grpcJoinRoundTripper) RoundTrip(ctx context.Context, req *v1.JoinRequest) (*v1.JoinResponse, error) {
	var err error
	for _, addr := range rt.Addrs {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		log := context.LoggerFrom(ctx).With("join-addr", addr)
		log.Debug("attempting to join node")
		if rt.AddressTimeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, rt.AddressTimeout)
			defer cancel()
		}
		var conn *grpc.ClientConn
		conn, err = grpc.DialContext(ctx, addr, rt.Credentials...)
		if err != nil {
			log.Debug("failed to dial node", "error", err)
			continue
		}
		defer conn.Close()
		log.Debug("dial successful")
		var resp *v1.JoinResponse
		resp, err = v1.NewMembershipClient(conn).Join(ctx, req)
		if err != nil {
			log.Debug("join request failed", "error", err)
			continue
		}
		log.Debug("join request successful")
		return resp, nil
	}
	if err != nil {
		// Return the last error if we have one.
		return nil, err
	}
	// We should never get here.
	return nil, errors.New("no addresses to dial")
}
