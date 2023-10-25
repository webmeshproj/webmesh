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
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/record"
	"github.com/libp2p/go-libp2p/p2p/host/peerstore/pstoremem"
)

var _ peerstore.Peerstore = (*UncertifiedPeerstore)(nil)

// UncertifiedPeerstore is a peerstore that does not verify peer addresses with
// signatures.
type UncertifiedPeerstore struct {
	peerstore.Peerstore
}

// NewUncertifiedPeerstore creates a new uncertified peerstore.
func NewUncertifiedPeerstore() (peerstore.Peerstore, error) {
	memstore, err := pstoremem.NewPeerstore()
	if err != nil {
		return nil, err
	}
	return &UncertifiedPeerstore{
		Peerstore: memstore,
	}, nil
}

func (ps *UncertifiedPeerstore) ConsumePeerRecord(s *record.Envelope, ttl time.Duration) (accepted bool, err error) {
	return true, nil
}

func (ps *UncertifiedPeerstore) GetPeerRecord(p peer.ID) *record.Envelope {
	return nil
}
