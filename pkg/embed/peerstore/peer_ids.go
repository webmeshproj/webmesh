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

package peerstore

import "github.com/libp2p/go-libp2p/core/peer"

type peerIDSlice peer.IDSlice

func (ps peerIDSlice) Upsert(p2 peer.ID) peerIDSlice {
	for _, peer := range ps {
		if peer == p2 {
			return ps
		}
	}
	return append(ps, p2)
}

func (ps peerIDSlice) Merge(p2 peerIDSlice) peerIDSlice {
	for _, peer := range p2 {
		ps = ps.Upsert(peer)
	}
	return ps
}

func (ps peerIDSlice) Remove(p peer.ID) peerIDSlice {
	for i, peer := range ps {
		if peer == p {
			return append(ps[:i], ps[i+1:]...)
		}
	}
	return ps
}

func (ps peerIDSlice) Copy() peer.IDSlice {
	out := make(peer.IDSlice, len(ps))
	copy(out, ps)
	return out
}
