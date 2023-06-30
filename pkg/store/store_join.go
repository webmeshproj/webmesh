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

package store

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	v1 "github.com/webmeshproj/api/v1"
	"golang.org/x/exp/slog"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/webmeshproj/node/pkg/context"
	"github.com/webmeshproj/node/pkg/net/wireguard"
	"github.com/webmeshproj/node/pkg/plugins/basicauth"
	"github.com/webmeshproj/node/pkg/plugins/ldap"
	"github.com/webmeshproj/node/pkg/util"
)

func (s *store) joinWithPeerDiscovery(ctx context.Context) error {
	log := s.log.With(slog.String("peer-discovery-addrs", strings.Join(s.opts.Mesh.PeerDiscoveryAddresses, ",")))
	ctx = context.WithLogger(ctx, log)
	log.Info("discovering joinable peers")
	var err error
	for _, addr := range s.opts.Mesh.PeerDiscoveryAddresses {
		var c *grpc.ClientConn
		c, err = s.newGRPCConn(ctx, addr)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.Error("failed to dial peer discovery address", slog.String("error", err.Error()))
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
			log.Error("failed to list peers", slog.String("error", err.Error()))
			continue
		}
		log.Info("discovered joinable peers", slog.Any("peers", resp.Peers))
	Peers:
		for _, peer := range resp.Peers {
			err = s.join(ctx, peer.Address, s.opts.Mesh.MaxJoinRetries)
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

func (s *store) join(ctx context.Context, joinAddr string, maxRetries int) error {
	log := s.log.With(slog.String("join-addr", joinAddr))
	ctx = context.WithLogger(ctx, log)
	log.Info("joining mesh")
	var tries int
	var err error
	for tries <= maxRetries {
		if tries > 0 {
			log.Info("retrying join request", slog.Int("tries", tries))
		}
		conn, err := s.newGRPCConn(ctx, joinAddr)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			err = fmt.Errorf("dial join node: %w", err)
			log.Error("gRPC dial failed", slog.String("error", err.Error()))
			tries++
			time.Sleep(time.Second)
			continue
		}
		err = s.joinWithConn(ctx, conn)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			err = fmt.Errorf("join node: %w", err)
			log.Error("join failed", slog.String("error", err.Error()))
			tries++
			time.Sleep(time.Second)
			continue
		}
		break
	}
	return err
}

func (s *store) joinWithConn(ctx context.Context, c *grpc.ClientConn) error {
	log := context.LoggerFrom(ctx)
	client := v1.NewNodeClient(c)
	defer c.Close()
	if s.opts.Mesh.GRPCPort == 0 {
		// Assume the default port.
		s.opts.Mesh.GRPCPort = 8443
	}
	key, err := s.loadWireGuardKey(ctx)
	if err != nil {
		return fmt.Errorf("load wireguard key: %w", err)
	}
	req := &v1.JoinRequest{
		Id:                 s.ID(),
		PublicKey:          key.PublicKey().String(),
		RaftPort:           int32(s.sl.ListenPort()),
		GrpcPort:           int32(s.opts.Mesh.GRPCPort),
		PrimaryEndpoint:    s.opts.Mesh.PrimaryEndpoint,
		WireguardEndpoints: s.opts.WireGuard.Endpoints,
		ZoneAwarenessId:    s.opts.Mesh.ZoneAwarenessID,
		AssignIpv4:         !s.opts.Mesh.NoIPv4,
		PreferRaftIpv6:     s.opts.Raft.PreferIPv6,
		AsVoter:            s.opts.Mesh.JoinAsVoter,
		Routes:             s.opts.Mesh.Routes,
		DirectPeers:        s.opts.Mesh.DirectPeers,
	}
	log.Debug("sending join request to node", slog.Any("req", req))
	resp, err := client.Join(ctx, req)
	if err != nil {
		return fmt.Errorf("join request: %w", err)
	}
	log.Debug("received join response", slog.Any("resp", resp))
	var addressv4, addressv6, networkv4, networkv6 netip.Prefix
	if !s.opts.Mesh.NoIPv4 {
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
	}
	if !s.opts.Mesh.NoIPv6 {
		if resp.AddressIpv6 != "" {
			addressv6, err = netip.ParsePrefix(resp.AddressIpv6)
			if err != nil {
				return fmt.Errorf("parse ipv6 address: %w", err)
			}
		}
		networkv6, err = netip.ParsePrefix(resp.NetworkIpv6)
		if err != nil {
			return fmt.Errorf("parse ipv6 network: %w", err)
		}
	}
	log.Info("configuring wireguard",
		slog.String("networkv4", addressv4.String()),
		slog.String("networkv6", addressv6.String()))
	opts := &ConfigureWireGuardOptions{
		Key:           key,
		AddressV4:     addressv4,
		AddressV6:     addressv6,
		MeshNetworkV4: networkv4,
		MeshNetworkV6: networkv6,
	}
	err = s.configureWireguard(ctx, opts)
	if err != nil {
		return fmt.Errorf("configure wireguard: %w", err)
	}
	var localCIDRs util.PrefixList
	if s.opts.Mesh.ZoneAwarenessID != "" {
		log.Info("using zone awareness, collecting local CIDRs")
		localCIDRs, err = util.DetectEndpoints(ctx, util.EndpointDetectOpts{
			DetectPrivate:  true,
			DetectIPv6:     !s.opts.Mesh.NoIPv6,
			SkipInterfaces: []string{s.wg.Name()},
		})
		log.Debug("detected local CIDRs", slog.Any("cidrs", localCIDRs.Strings()))
		if err != nil {
			return fmt.Errorf("detect endpoints: %w", err)
		}
	}
	for _, peer := range resp.GetPeers() {
		key, err := wgtypes.ParseKey(peer.GetPublicKey())
		if err != nil {
			return fmt.Errorf("parse peer key: %w", err)
		}
		var endpoint netip.AddrPort
		var addr *net.UDPAddr
		if peer.GetIce() {
			// We are peered with this node via ICE.
			if len(resp.GetIceServers()) == 0 {
				return fmt.Errorf("no ICE servers provided")
			}
			// TODO: Try all ICE servers
			addr, err = s.negotiateWireGuardICEConnection(ctx, resp.GetIceServers()[0], peer)
		} else {
			addr, err = net.ResolveUDPAddr("udp", peer.GetPrimaryEndpoint())
		}
		if err != nil {
			log.Error("could not resolve peer primary endpoint", slog.String("error", err.Error()))
		} else {
			if addr.AddrPort().Addr().Is4In6() {
				// This is an IPv4 address masquerading as an IPv6 address.
				// We need to convert it to a real IPv4 address.
				// This is a workaround for a bug in Go's net package.
				addr = &net.UDPAddr{
					IP:   addr.IP.To4(),
					Port: addr.Port,
					Zone: addr.Zone,
				}
			}
			endpoint = addr.AddrPort()
		}
		if !peer.GetIce() && s.opts.Mesh.ZoneAwarenessID != "" && peer.GetZoneAwarenessId() != "" {
			if peer.GetZoneAwarenessId() == s.opts.Mesh.ZoneAwarenessID {
				if !localCIDRs.Contains(endpoint.Addr()) && len(peer.GetWireguardEndpoints()) > 0 {
					// We share zone awareness with the peer and their primary endpoint
					// is not in one of our local CIDRs. We'll try to use one of their
					// additional endpoints instead.
					for _, additionalEndpoint := range peer.GetWireguardEndpoints() {
						addr, err := net.ResolveUDPAddr("udp", additionalEndpoint)
						if err != nil {
							log.Error("could not resolve peer primary endpoint", slog.String("error", err.Error()))
							continue
						}
						if addr.AddrPort().Addr().Is4In6() {
							// Same as above, this is an IPv4 address masquerading as an IPv6 address.
							addr = &net.UDPAddr{
								IP:   addr.IP.To4(),
								Port: addr.Port,
								Zone: addr.Zone,
							}
						}
						log.Debug("evalauting zone awareness endpoint",
							slog.String("endpoint", addr.String()),
							slog.String("zone", peer.GetZoneAwarenessId()))
						ep := addr.AddrPort()
						if localCIDRs.Contains(ep.Addr()) {
							// We found an additional endpoint that is in one of our local
							// CIDRs. We'll use this one instead.
							log.Info("zone awareness shared with peer, using LAN endpoint", slog.String("endpoint", ep.String()))
							endpoint = ep
							break
						}
					}
				}
			}
		}
		allowedIPs := make([]netip.Prefix, len(peer.GetAllowedIps()))
		for i, ip := range peer.GetAllowedIps() {
			allowedIPs[i], err = netip.ParsePrefix(ip)
			if err != nil {
				return fmt.Errorf("parse peer allowed ip: %w", err)
			}
		}
		allowedRoutes := make([]netip.Prefix, len(peer.GetAllowedRoutes()))
		for i, ip := range peer.GetAllowedRoutes() {
			allowedRoutes[i], err = netip.ParsePrefix(ip)
			if err != nil {
				return fmt.Errorf("parse peer allowed route: %w", err)
			}
		}
		wgpeer := wireguard.Peer{
			ID:         peer.GetId(),
			PublicKey:  key,
			Endpoint:   endpoint,
			AllowedIPs: allowedIPs,
		}
		log.Info("adding wireguard peer", slog.Any("peer", &wgpeer))
		err = s.wg.PutPeer(ctx, &wgpeer)
		if err != nil {
			return err
		}
		// Try to ping the peer to establish a connection
		// TODO: Only do this if we are a private node
		go func(peer *v1.WireGuardPeer) {
			// TODO: make this configurable
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			var addr netip.Prefix
			var err error
			if peer.AddressIpv4 != "" {
				addr, err = netip.ParsePrefix(peer.AddressIpv4)
			} else {
				addr, err = netip.ParsePrefix(peer.AddressIpv6)
			}
			if err != nil {
				log.Warn("could not parse address", slog.String("error", err.Error()))
				return
			}
			err = util.Ping(ctx, addr.Addr())
			if err != nil {
				log.Warn("could not ping descendant", slog.String("descendant", peer.Id), slog.String("error", err.Error()))
				return
			}
			log.Debug("successfully pinged descendant", slog.String("descendant", peer.Id))
		}(peer)
	}
	return nil
}

func (s *store) newGRPCConn(ctx context.Context, addr string) (*grpc.ClientConn, error) {
	return grpc.DialContext(ctx, addr, s.grpcCreds(ctx)...)
}

func (s *store) grpcCreds(ctx context.Context) []grpc.DialOption {
	log := context.LoggerFrom(ctx)
	var opts []grpc.DialOption
	if s.opts.TLS.Insecure {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		// MTLS is included in the TLS config already if enabled.
		log.Debug("using TLS credentials")
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(s.tlsConfig)))
	}
	if s.opts.Auth != nil {
		if s.opts.Auth.Basic != nil {
			log.Debug("using basic auth credentials")
			opts = append(opts, basicauth.NewCreds(s.opts.Auth.Basic.Username, s.opts.Auth.Basic.Password))
		} else if s.opts.Auth.LDAP != nil {
			log.Debug("using LDAP auth credentials")
			opts = append(opts, ldap.NewCreds(s.opts.Auth.LDAP.Username, s.opts.Auth.LDAP.Password))
		}
	}
	return opts
}
