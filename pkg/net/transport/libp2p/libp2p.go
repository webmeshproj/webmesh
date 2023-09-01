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

// Package libp2p provides discovery mechanisms using Kademlia DHT.
package libp2p

import (
	"strings"
	"sync"

	"github.com/libp2p/go-libp2p/core/protocol"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/net/system/buffers"
)

// JoinProtocol is the protocol used for joining a mesh.
const JoinProtocol = protocol.ID("/webmesh/join/0.0.1")

// WebRTCSignalProtocol is the protocol used for webrtc-signaling.
const WebRTCSignalProtocol = protocol.ID("/webmesh/signal/0.0.1")

// WebRTCSignalProtocolFor returns the protocol used for webrtc-signaling for the given
// rendevous string or peer ID.
func WebRTCSignalProtocolFor(id string) protocol.ID {
	return protocol.ID("/webmesh/signal/0.0.1/" + id)
}

// WebRTCRendevousFrom returns the rendevous string from the given protocol ID.
func WebRTCRendevousFrom(id protocol.ID) string {
	if len(id) <= len(WebRTCSignalProtocol)+1 {
		return ""
	}
	return strings.TrimPrefix(string(id), string(WebRTCSignalProtocol)+"/")
}

var buffersOnce sync.Once

// SetBuffers sets the buffers to use for libp2p.
func SetBuffers(ctx context.Context) {
	buffersOnce.Do(func() {
		log := context.LoggerFrom(ctx)
		err := buffers.SetMaximumReadBuffer(2500000)
		if err != nil {
			log.Warn("Failed to set maximum read buffer", "error", err.Error())
		}
		err = buffers.SetMaximumWriteBuffer(2500000)
		if err != nil {
			log.Warn("Failed to set maximum write buffer", "error", err.Error())
		}
	})
}
