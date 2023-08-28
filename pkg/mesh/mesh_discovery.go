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

package mesh

import (
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/multiformats/go-multiaddr"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/proto"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/net/transport/libp2p"
)

func (s *meshStore) AnnounceDHT(ctx context.Context, opts *DiscoveryOptions) error {
	log := context.LoggerFrom(ctx)
	log.Info("Announcing peer discovery service")
	var peers []multiaddr.Multiaddr
	for _, p := range opts.KadBootstrapServers {
		mul, err := multiaddr.NewMultiaddr(p)
		if err != nil {
			return fmt.Errorf("new multiaddr: %w", err)
		}
		peers = append(peers, mul)
	}
	discover, err := libp2p.NewKadDHTAnnouncer(ctx, libp2p.DHTAnnounceOptions{
		PSK:            opts.PSK,
		BootstrapPeers: peers,
		DiscoveryTTL:   time.Minute, // TODO: Make this configurable
	})
	if err != nil {
		return fmt.Errorf("new kad dht announcer: %w", err)
	}
	if err := discover.Start(ctx); err != nil {
		return fmt.Errorf("start peer discovery: %w", err)
	}
	go func() {
		for {
			conn, err := discover.Accept()
			if err != nil {
				log.Error("failed to accept peer connection from discovery service", slog.String("error", err.Error()))
				return
			}
			s.log.Debug("Got connection to peer via Kad DHT")
			go s.handleIncomingDiscoveryPeer(conn)
		}
	}()
	s.discovermu.Lock()
	s.discoveries[opts.PSK] = discover
	s.discovermu.Unlock()
	return nil
}

func (s *meshStore) LeaveDHT(ctx context.Context, psk string) error {
	s.discovermu.Lock()
	defer s.discovermu.Unlock()
	if d, ok := s.discoveries[psk]; ok {
		if err := d.Stop(); err != nil {
			return err
		}
		delete(s.discoveries, psk)
	}
	return nil
}

func (s *meshStore) handleIncomingDiscoveryPeer(conn io.ReadWriteCloser) {
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15) // TODO: Make this configurable
	defer cancel()
	// Read a join request off the wire
	var req v1.JoinRequest
	b := make([]byte, 8192)
	n, err := conn.Read(b)
	if err != nil {
		s.log.Error("failed to read join request from discovered peer", slog.String("error", err.Error()))
		return
	}
	if err := proto.Unmarshal(b[:n], &req); err != nil {
		s.log.Error("failed to unmarshal join request from discovered peer", slog.String("error", err.Error()))
		b = []byte("ERROR: " + err.Error())
		if _, err := conn.Write(b); err != nil {
			s.log.Error("failed to write error to discovered peer", slog.String("error", err.Error()))
		}
		return
	}
	// Forward the request to the leader
	c, err := s.DialLeader(ctx)
	if err != nil {
		s.log.Error("failed to dial leader", slog.String("error", err.Error()))
		b = []byte("ERROR: " + err.Error())
		if _, err := conn.Write(b); err != nil {
			s.log.Error("failed to write error to discovered peer", slog.String("error", err.Error()))
		}
		return
	}
	defer c.Close()
	resp, err := v1.NewMembershipClient(c).Join(ctx, &req)
	if err != nil {
		s.log.Error("failed to join cluster", slog.String("error", err.Error()))
		// Attempt to write the raw error back to the peer
		b = []byte("ERROR: " + err.Error())
		if _, err := conn.Write(b); err != nil {
			s.log.Error("failed to write error to discovered peer", slog.String("error", err.Error()))
		}
		return
	}
	// Write the response back to the peer
	b, err = proto.Marshal(resp)
	if err != nil {
		s.log.Error("failed to marshal join response", slog.String("error", err.Error()))
		b = []byte("ERROR: " + err.Error())
		if _, err := conn.Write(b); err != nil {
			s.log.Error("failed to write error to discovered peer", slog.String("error", err.Error()))
		}
		return
	}
	if _, err := conn.Write(b); err != nil {
		s.log.Error("failed to write join response to discovered peer", slog.String("error", err.Error()))
		return
	}
}
