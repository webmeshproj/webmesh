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
	"context"
	"io"

	v1 "github.com/webmeshproj/api/go/v1"
)

// RoundTripper is a generic interface for executing a request and returning
// a response.
type RoundTripper[REQ, RESP any] interface {
	io.Closer

	RoundTrip(ctx context.Context, req *REQ) (*RESP, error)
}

// RoundTripperFunc is a function that implements RoundTripper.
type RoundTripperFunc[REQ, RESP any] func(ctx context.Context, req *REQ) (*RESP, error)

// RoundTrip implements RoundTripper.
func (f RoundTripperFunc[REQ, RESP]) RoundTrip(ctx context.Context, req *REQ) (*RESP, error) {
	return f(ctx, req)
}

// RoundTrip implements RoundTripper.
func (f RoundTripperFunc[REQ, RESP]) Close() error {
	return nil
}

// JoinRoundTripper is the interface for joining a cluster.
type JoinRoundTripper = RoundTripper[v1.JoinRequest, v1.JoinResponse]

// JoinRoundTripperFunc is a function that implements JoinRoundTripper.
type JoinRoundTripperFunc = RoundTripperFunc[v1.JoinRequest, v1.JoinResponse]

// LeaveRoundTripper is the interface for leaving a cluster.
type LeaveRoundTripper = RoundTripper[v1.LeaveRequest, v1.LeaveResponse]

// LeaveRoundTripperFunc is a function that implements LeaveRoundTripper.
type LeaveRoundTripperFunc = RoundTripperFunc[v1.LeaveRequest, v1.LeaveResponse]

// UnaryServer is the interface for handling unary requests.
type UnaryServer[REQ, RESP any] interface {
	// Serve is executed when a unary request is received.
	Serve(ctx context.Context, req *REQ) (*RESP, error)
}

// UnaryServerFunc is a function that implements UnaryServer.
type UnaryServerFunc[REQ, RESP any] func(ctx context.Context, req *REQ) (*RESP, error)

// Serve implements UnaryServer.
func (f UnaryServerFunc[REQ, RESP]) Serve(ctx context.Context, req *REQ) (*RESP, error) {
	return f(ctx, req)
}

// JoinServer is the interface for handling requests to join a cluster.
type JoinServer = UnaryServer[v1.JoinRequest, v1.JoinResponse]

// JoinServerFunc is a function that implements JoinServer.
type JoinServerFunc = UnaryServerFunc[v1.JoinRequest, v1.JoinResponse]
