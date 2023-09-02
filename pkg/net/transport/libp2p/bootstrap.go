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
	"time"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/net/transport"
)

// BootstrapOptions are options for the bootstrap transport.
type BootstrapOptions struct {
	// Rendezvous is the rendezvous string to use for the transport.
	Rendezvous string
	// Host are options for configuring the host.
	Host HostOptions
	// ElectionTimeout is the election timeout.
	ElectionTimeout time.Duration
}

// NewBootstrapTransport creates a new bootstrap transport.
func NewBootstrapTransport(ctx context.Context, opts BootstrapOptions) (transport.BootstrapTransport, error) {
	return &bootstrapTransport{}, errors.New("bootstrap transport not supported")
}

type bootstrapTransport struct{}

func (b *bootstrapTransport) LeaderElect(ctx context.Context) (isLeader bool, rt transport.JoinRoundTripper, err error) {
	return false, nil, nil
}
