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

	"github.com/webmeshproj/webmesh/pkg/context"
	meshdiscovery "github.com/webmeshproj/webmesh/pkg/discovery"
)

// KadDHTOptions are the options for creating a new libp2p kademlia DHT.
type KadDHTOptions struct {
}

// NewKadDHTAnnouncer creates a new announcer for the libp2p kademlia DHT.
func NewKadDHTAnnouncer(ctx context.Context, opts *KadDHTOptions) (meshdiscovery.Discovery, error) {
	return nil, errors.New("not implemented")
}

// NewKadDHTJoiner creates a new joiner for the libp2p kademlia DHT.
func NewKadDHTJoiner(ctx context.Context, opts *KadDHTOptions) (meshdiscovery.Discovery, error) {
	return nil, errors.New("not implemented")
}
