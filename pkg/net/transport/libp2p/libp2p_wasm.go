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
	"io"

	"github.com/hashicorp/raft"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/net/transport"
)

type AnnounceOptions struct {
}

func NewAnnouncer(ctx context.Context, opts DHTAnnounceOptions, join transport.JoinServer) (io.Closer, error) {
	return nil, errors.New("not implemented")
}

type RoundTripOptions struct {
}

func NewJoinRoundTripper(opts RoundTripOptions) transport.JoinRoundTripper {
	return nil, errors.New("not implemented")
}

// RaftTransportOptions are options for the TCP transport.
type RaftTransportOptions struct {
}

// NewRaftTransport creates a new Raft transport over the Kademlia DHT.
func NewRaftTransport(ctx context.Context, opts RaftTransportOptions) (raft.Transport, error) {
	return nil, errors.New("not implemented")
}

// WebRTCExternalSignalOptions are options for configuring a WebRTC signaling transport.
type WebRTCExternalSignalOptions struct{}

// NewExternalSignalTransport returns a new WebRTC signaling transport that attempts
// to negotiate a WebRTC connection using the Webmesh WebRTC signaling server. This is
// typically used by clients trying to create a proxy connection to a server.
func NewExternalSignalTransport(opts WebRTCExternalSignalOptions) (transport.WebRTCSignalTransport, error) {
	return nil, errors.New("not implemented")
}
