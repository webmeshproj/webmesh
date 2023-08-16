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
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	v1 "github.com/webmeshproj/api/v1"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/webmeshproj/webmesh/pkg/campfire"
	"github.com/webmeshproj/webmesh/pkg/context"
	meshnet "github.com/webmeshproj/webmesh/pkg/net"
)

var (
	errFatalJoin = fmt.Errorf("fatal join error")
)

func (s *meshStore) joinWithPeerDiscovery(ctx context.Context, features []v1.Feature) error {
	log := s.log.With(slog.String("peer-discovery-addrs", strings.Join(s.opts.Mesh.PeerDiscoveryAddresses, ",")))
	ctx = context.WithLogger(ctx, log)
	log.Info("Joining mesh via peer discovery")
	var err error
	for _, addr := range s.opts.Mesh.PeerDiscoveryAddresses {
		var c *grpc.ClientConn
		c, err = s.newGRPCConn(ctx, addr)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.Error("Failed to dial peer discovery address", slog.String("error", err.Error()))
			continue
		}
		defer c.Close()
		cli := v1.NewPeerDiscoveryClient(c)
		var resp *v1.ListRaftPeersResponse
		resp, err = cli.ListPeers(ctx, &emptypb.Empty{})
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.Error("Failed to list peers", slog.String("error", err.Error()))
			continue
		}
		log.Info("Discovered joinable peers", slog.Any("peers", resp.Peers))
	Peers:
		for _, peer := range resp.Peers {
			err = s.join(ctx, features, peer.Address)
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				log.Error("failed to join peer", slog.String("error", err.Error()))
				continue Peers
			}
		}
		// If we got this far, we aren't going to try another discovery server.
		// They'll all have the same peers.
		break
	}
	if err != nil {
		return fmt.Errorf("join with peer discovery: %w", err)
	}
	return nil
}

func (s *meshStore) joinByCampfire(ctx context.Context, features []v1.Feature) error {
	log := s.log.With(slog.String("join-method", "campfire"))
	uri, err := campfire.ParseCampfireURI(s.opts.Mesh.JoinCampfireURI)
	if err != nil {
		return fmt.Errorf("parse campfire uri: %w", err)
	}
	ctx = context.WithLogger(ctx, log)
	log.Info("Joining mesh via campfire")
	var tries int
	for tries <= s.opts.Mesh.MaxJoinRetries {
		// The initial connection should be fast, if it isn't,
		// the most likely cause is that no one is waiting for us.
		joinCtx, cancel := context.WithTimeout(ctx, time.Second*5)
		defer cancel()
		conn, err := campfire.Join(joinCtx, uri)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			err = fmt.Errorf("join campfire: %w", err)
			log.Error("Join campfire failed", slog.String("error", err.Error()))
			if tries >= s.opts.Mesh.MaxJoinRetries {
				return err
			}
			tries++
			time.Sleep(time.Second)
			continue
		}
		defer conn.Close()
		log.Info("Established campfire connection, joining mesh")
		key, err := s.loadWireGuardKey(ctx)
		if err != nil {
			return fmt.Errorf("load wireguard key: %w", err)
		}
		req := s.newJoinRequest(features, key)
		log.Debug("Sending join request over campfire", slog.Any("req", req))
		data, err := proto.Marshal(req)
		if err != nil {
			// This should never happen
			return fmt.Errorf("marshal join request: %w", err)
		}
		_, err = conn.Write(data)
		if err != nil {
			log.Error("Failed to send join request over campfire", slog.String("error", err.Error()))
			// We'll retry
			continue
		}
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			log.Error("Failed to read join response over campfire", slog.String("error", err.Error()))
			// We'll retry
			continue
		}
		var resp v1.JoinResponse
		err = proto.Unmarshal(buf[:n], &resp)
		if err != nil {
			// This could mean an actual error from the join server
			log.Warn("Failed to unmarshal join response over campfire", slog.String("error", err.Error()))
			return fmt.Errorf("campfire join error: %s", string(buf[:n]))
		}
		log.Info("Received join response over campfire", slog.Any("resp", &resp))
		err = s.handleJoinResponse(context.WithLogger(context.Background(), log), &resp, key)
		if err != nil {
			if errors.Is(err, errFatalJoin) {
				return err
			}
			// We'll retry
			log.Error("Failed to handle join response", slog.String("error", err.Error()))
			continue
		}
		return nil
	}
	return errFatalJoin
}

func (s *meshStore) join(ctx context.Context, features []v1.Feature, joinAddr string) error {
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
		err = s.joinWithConn(ctx, conn, features)
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

func (s *meshStore) joinWithConn(ctx context.Context, c *grpc.ClientConn, features []v1.Feature) error {
	log := context.LoggerFrom(ctx)
	defer c.Close()
	key, err := s.loadWireGuardKey(ctx)
	if err != nil {
		return fmt.Errorf("load wireguard key: %w", err)
	}
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
