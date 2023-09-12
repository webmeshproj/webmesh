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

package security

import (
	"bufio"
	"bytes"
	"fmt"
	"net/netip"
	"strings"

	"github.com/libp2p/go-libp2p/core/network"

	"github.com/webmeshproj/webmesh/pkg/context"
	wmcrypto "github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/net/wireguard"
)

// HandleEndpointNegotiation handles the endpoint negotiation for an inbound
// or outbound webmesh connection.
func HandleEndpointNegotiation(ctx context.Context, stream network.Stream, iface wireguard.Interface, key wmcrypto.PrivateKey, endpoints []string) error {
	defer func() { _ = stream.Reset() }()
	log := context.LoggerFrom(ctx)
	log.Info("Received inbound webmesh connection, negotiating endpoints")
	rw := bufio.NewReadWriter(bufio.NewReader(stream), bufio.NewWriter(stream))
	// Make sure the peer has already been put in wireguard
	peer, ok := iface.Peers()[stream.Conn().RemotePeer().ShortString()]
	if !ok {
		log.Error("Peer not found in wireguard interface")
		return fmt.Errorf("peer not found in wireguard interface")
	}
	// We write a comma separated list of our endpoints (if any) to the stream.
	// We then follow it with a null byte and then a signature of the endpoints,
	// finally followed by a newline.
	// The remote peer will then do the same.
	var payload []byte
	if len(endpoints) > 0 {
		data := []byte(strings.Join(endpoints, ","))
		sig, err := key.Sign(data)
		if err != nil {
			log.Error("Failed to sign endpoints", "err", err)
			return fmt.Errorf("failed to sign endpoints: %w", err)
		}
		payload = []byte(fmt.Sprintf("%s\x00%s\n", data, string(sig)))
	} else {
		// Just the null byte
		payload = []byte("\x00")
	}
	_, err := rw.Write(payload)
	if err != nil {
		log.Error("Failed to write endpoints", "err", err)
		return fmt.Errorf("failed to write endpoints: %w", err)
	}
	// Flush the payload in a goroutine so we can read the response.
	go func() {
		if err := rw.Flush(); err != nil {
			log.Error("Failed to flush endpoints", "err", err)
			return
		}
	}()
	// We expected the same from the remote side.
	// We read the payload and verify the signature.
	// If the signature is valid, we add the endpoints to the peer.
	data, err := rw.ReadBytes('\n')
	if err != nil {
		log.Error("Failed to read endpoints", "err", err)
		return fmt.Errorf("failed to read endpoints: %w", err)
	}
	// Split the data into the endpoints and the signature.
	parts := bytes.Split(data, []byte("\x00"))
	if len(parts) != 2 {
		log.Error("Invalid endpoints payload")
		return fmt.Errorf("invalid endpoints payload")
	}
	eps, sig := bytes.TrimSpace(parts[0]), bytes.TrimSpace(parts[1])
	// If endpoints and signature are empty we are done.
	if len(eps) == 0 && len(sig) == 0 {
		log.Debug("No endpoints to add")
		return nil
	}
	// Verify the signature.
	ok, err = peer.PublicKey.Verify([]byte(eps), []byte(sig))
	if err != nil {
		log.Error("Failed to verify endpoints signature", "err", err)
		return fmt.Errorf("failed to verify endpoints signature: %w", err)
	}
	if !ok {
		log.Error("Invalid endpoints signature")
		return fmt.Errorf("invalid endpoints signature")
	}
	// Parse the endpoints.
	epStrings := strings.Split(string(eps), ",")
	if len(epStrings) == 0 {
		// Nothing to do
		return nil
	}
	// Pick the first one in the list for now. But negotiation
	// should continue until a connection can be established.
	epString := epStrings[0]
	addrport, err := netip.ParseAddrPort(epString)
	if err != nil {
		log.Error("Failed to parse endpoint", "endpoint", epString, "err", err)
		return fmt.Errorf("failed to parse endpoint %s: %w", epString, err)
	}
	peer.Endpoint = addrport
	err = iface.PutPeer(ctx, &peer)
	if err != nil {
		log.Error("Failed to update peer in wireguard interface", "err", err)
		return fmt.Errorf("failed to add peer to wireguard interface: %w", err)
	}
	return nil
}
