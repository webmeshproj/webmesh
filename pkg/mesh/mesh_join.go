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
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	v1 "github.com/webmeshproj/api/v1"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	"github.com/webmeshproj/webmesh/pkg/context"
	meshnet "github.com/webmeshproj/webmesh/pkg/net"
)

var (
	errFatalJoin = fmt.Errorf("fatal join error")
)

func (s *meshStore) join(ctx context.Context, features []v1.Feature, joinAddr string, key wgtypes.Key) error {
	log := s.log.With(slog.String("join-addr", joinAddr))
	ctx = context.WithLogger(ctx, log)
	log.Info("Joining mesh via gRPC")
	var tries int
	var err error
	for tries <= s.opts.Mesh.MaxJoinRetries {
		if tries > 0 {
			log.Info("Retrying join request", slog.Int("tries", tries))
		}
		var conn *grpc.ClientConn
		conn, err = s.newGRPCConn(ctx, joinAddr)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			err = fmt.Errorf("dial join node: %w", err)
			log.Error("gRPC dial failed", slog.String("error", err.Error()))
			if tries >= s.opts.Mesh.MaxJoinRetries {
				return err
			}
			tries++
			time.Sleep(time.Second)
			continue
		}
		err = s.joinWithConn(ctx, conn, features, key)
		if err != nil {
			if errors.Is(err, errFatalJoin) {
				return err
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			err = fmt.Errorf("join node: %w", err)
			log.Error("Join request failed", slog.String("error", err.Error()))
			if tries >= s.opts.Mesh.MaxJoinRetries {
				return err
			}
			tries++
			time.Sleep(time.Second)
			continue
		}
		break
	}
	return err
}

func (s *meshStore) joinWithKadDHT(ctx context.Context, features []v1.Feature, key wgtypes.Key) error {
	s.log.Info("Joining mesh via Kad DHT")
	discover, err := s.newDiscoveryJoiner(ctx)
	if err != nil {
		return fmt.Errorf("new kad dht joiner: %w", err)
	}
	if err := discover.Start(ctx); err != nil {
		return fmt.Errorf("start peer discovery: %w", err)
	}
	defer func() {
		err := discover.Stop()
		if err != nil {
			s.log.Error("error stopping discovery service", slog.String("error", err.Error()))
		}
	}()
	conn, err := discover.Accept()
	if err != nil {
		return fmt.Errorf("accept peer stream: %w", err)
	}
	defer conn.Close()
	s.log.Debug("Got connection to peer via Kad DHT")
	// Send a join request to the peer
	req := s.newJoinRequest(features, key)
	data, err := proto.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal join request: %w", err)
	}
	_, err = conn.Write(data)
	if err != nil {
		return fmt.Errorf("write join request: %w", err)
	}
	// Read a join response from the peer
	var resp v1.JoinResponse
	b := make([]byte, 8192)
	n, err := conn.Read(b)
	if err != nil {
		if err != io.EOF && n == 0 {
			return fmt.Errorf("read join response: %w", err)
		}
	}
	if bytes.HasPrefix(b[:n], []byte("ERROR: ")) {
		return fmt.Errorf("join error: %s", string(b[:n]))
	}
	if err := proto.Unmarshal(b[:n], &resp); err != nil {
		return fmt.Errorf("unmarshal join response: %w", err)
	}
	return s.handleJoinResponse(ctx, &resp, key)
}

func (s *meshStore) joinWithConn(ctx context.Context, c *grpc.ClientConn, features []v1.Feature, key wgtypes.Key) error {
	log := context.LoggerFrom(ctx)
	defer c.Close()
	req := s.newJoinRequest(features, key)
	log.Debug("Sending join request to node", slog.Any("req", req))
	resp, err := s.doJoinGRPC(ctx, c, req)
	if err != nil {
		return fmt.Errorf("join request: %w", err)
	}
	return s.handleJoinResponse(ctx, resp, key)
}

func (s *meshStore) handleJoinResponse(ctx context.Context, resp *v1.JoinResponse, key wgtypes.Key) error {
	log := context.LoggerFrom(ctx)
	log.Debug("Received join response", slog.Any("resp", resp))
	s.meshDomain = resp.GetMeshDomain()
	if !strings.HasSuffix(s.meshDomain, ".") {
		s.meshDomain += "."
	}
	var addressv4, addressv6, networkv4, networkv6 netip.Prefix
	var err error
	// We always parse addresses and let the net manager decide what to use
	if resp.AddressIpv4 != "" {
		addressv4, err = netip.ParsePrefix(resp.AddressIpv4)
		if err != nil {
			return fmt.Errorf("parse ipv4 address: %w", err)
		}
	}
	networkv4, err = netip.ParsePrefix(resp.NetworkIpv4)
	if err != nil {
		return fmt.Errorf("parse ipv4 network: %w", err)
	}
	addressv6, err = netip.ParsePrefix(resp.AddressIpv6)
	if err != nil {
		return fmt.Errorf("parse ipv6 address: %w", err)
	}
	networkv6, err = netip.ParsePrefix(resp.NetworkIpv6)
	if err != nil {
		return fmt.Errorf("parse ipv6 network: %w", err)
	}
	opts := &meshnet.StartOptions{
		Key:       key,
		AddressV4: addressv4,
		AddressV6: addressv6,
		NetworkV4: networkv4,
		NetworkV6: networkv6,
	}
	log.Debug("Starting network manager", slog.Any("opts", opts))
	err = s.nw.Start(ctx, opts)
	if err != nil {
		return fmt.Errorf("%w starting network manager: %w", errFatalJoin, err)
	}
	for _, peer := range resp.GetPeers() {
		log.Debug("Adding peer", slog.Any("peer", peer))
		err = s.nw.AddPeer(ctx, peer, resp.GetIceServers())
		if err != nil {
			log.Error("Failed to add peer", slog.String("error", err.Error()))
		}
	}
	if s.opts.Mesh.UseMeshDNS {
		var servers []netip.AddrPort
		if s.opts.Mesh.MeshDNSAdvertisePort != 0 {
			// Use our local port.
			addr := "127.0.0.1"
			if s.opts.Mesh.NoIPv4 {
				addr = "::1"
			}
			servers = append(servers, netip.AddrPortFrom(netip.MustParseAddr(addr), uint16(s.opts.Mesh.MeshDNSAdvertisePort)))
		} else {
			for _, server := range resp.GetDnsServers() {
				addr, err := netip.ParseAddrPort(server)
				if err != nil {
					return fmt.Errorf("%w parsing dns server: %w", errFatalJoin, err)
				}
				servers = append(servers, addr)
			}
		}
		err = s.nw.AddDNSServers(ctx, servers)
		if err != nil {
			log.Error("Failed to add dns servers", slog.String("error", err.Error()))
		}
	}
	return nil
}

func (s *meshStore) doJoinGRPC(ctx context.Context, c *grpc.ClientConn, req *v1.JoinRequest) (*v1.JoinResponse, error) {
	context.LoggerFrom(ctx).Debug("Sending join request to node over gRPC", slog.Any("req", req))
	return v1.NewMembershipClient(c).Join(ctx, req)
}

func (s *meshStore) newJoinRequest(features []v1.Feature, key wgtypes.Key) *v1.JoinRequest {
	if s.opts.Mesh.GRPCAdvertisePort <= 0 {
		// Assume the default port.
		s.opts.Mesh.GRPCAdvertisePort = DefaultGRPCPort
	}
	req := &v1.JoinRequest{
		Id:                 s.ID(),
		PublicKey:          key.PublicKey().String(),
		RaftPort:           int32(s.raft.ListenPort()),
		GrpcPort:           int32(s.opts.Mesh.GRPCAdvertisePort),
		MeshdnsPort:        int32(s.opts.Mesh.MeshDNSAdvertisePort),
		PrimaryEndpoint:    s.opts.Mesh.PrimaryEndpoint,
		WireguardEndpoints: s.opts.WireGuard.Endpoints,
		ZoneAwarenessId:    s.opts.Mesh.ZoneAwarenessID,
		AssignIpv4:         !s.opts.Mesh.NoIPv4,
		PreferRaftIpv6:     s.opts.Raft.PreferIPv6,
		AsVoter:            s.opts.Mesh.JoinAsVoter,
		AsObserver:         s.opts.Mesh.JoinAsObserver,
		Routes:             s.opts.Mesh.Routes,
		DirectPeers:        s.opts.Mesh.DirectPeers,
		Features:           features,
	}
	return req
}
