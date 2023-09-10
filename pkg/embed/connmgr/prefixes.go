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

package connmgr

import (
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

// StorageKey is a key prefix for values in the database.
type StorageKey string

// Prefixes used in the database. All get appended with the
// peer ID to produce paths such as /tags/<peer ID>.
const (
	// Tags is the key prefix for tags.
	Tags StorageKey = "/tags"
	// Connections is the key prefix for connections
	Connections StorageKey = "/connections"
	// Listeners is the key prefix for listeners.
	Listeners StorageKey = "/listeners"
)

// Key returns this key as a byte slice.
func (p StorageKey) Key() []byte { return []byte(p) }

// Key returns this key as a string.
func (p StorageKey) String() string { return string(p) }

// PathFor computes the path for this key based on the given peer ID.
func (p StorageKey) PathFor(peer peer.ID) StorageKey {
	return StorageKey(p.String() + "/" + peer.String())
}

// TagFor computes the key for the tag based on the given value.
func (p StorageKey) TagFor(value string) StorageKey {
	return StorageKey(p.String() + "/" + value)
}

// TimeFor computes the key for a connection time based on the given value.
func (p StorageKey) TimeFor(value time.Time) StorageKey {
	return StorageKey(p.String() + "/" + value.Format(time.RFC3339Nano))
}

// AddrFor computes the key for a listener address based on the given value.
func (p StorageKey) AddrFor(value ma.Multiaddr) StorageKey {
	// Strip the leading slash from the address so we can
	// parse cleanly on return.
	addr := value.String()[1:]
	return StorageKey(p.String() + "/" + addr)
}

// Trim strips the prefix from the given key.
func (p StorageKey) Trim(key []byte) []byte {
	len := len(p)
	return key[len:]
}
