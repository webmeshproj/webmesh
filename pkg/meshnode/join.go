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

package meshnode

import (
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/meshnet"
	"github.com/webmeshproj/webmesh/pkg/services"
)

func (s *meshStore) join(ctx context.Context, opts ConnectOptions) error {
	log := s.log
	ctx = context.WithLogger(ctx, log)
	log.Info("Joining webmesh cluster")
	defer opts.JoinRoundTripper.Close()
	var tries int
	encoded, err := s.key.PublicKey().Encode()
	if err != nil {
		return fmt.Errorf("encode public key: %w", err)
	}
	for tries <= opts.MaxJoinRetries {
		if tries > 0 {
			log.Info("Retrying join request", slog.Int("tries", tries))
		}
		req := s.newJoinRequest(opts, encoded)
		log.Debug("Sending join request to node", slog.Any("req", req))
		resp, err := opts.JoinRoundTripper.RoundTrip(ctx, req)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			err = fmt.Errorf("join: %w", err)
			log.Error("Join request failed", slog.String("error", err.Error()))
			if tries >= opts.MaxJoinRetries {
				return err
			}
			tries++
			time.Sleep(time.Second)
			continue
		}
		err = s.handleJoinResponse(ctx, opts, resp)
		if err != nil {
			return fmt.Errorf("handle join response: %w", err)
		}
		break
	}
	return nil
}

func (s *meshStore) handleJoinResponse(ctx context.Context, opts ConnectOptions, resp *v1.JoinResponse) error {
	log := context.LoggerFrom(ctx)
	log.Debug("Received join response", slog.Any("resp", resp))
	s.meshDomain = resp.GetMeshDomain()
	if !strings.HasSuffix(s.meshDomain, ".") {
		s.meshDomain += "."
	}
	var addressv4, addressv6, networkv4, networkv6 netip.Prefix
	var err error
	// We always parse addresses and let the net manager decide what to use
	if resp.GetAddressIPv4() != "" {
		addressv4, err = netip.ParsePrefix(resp.GetAddressIPv4())
		if err != nil {
			return fmt.Errorf("parse ipv4 address: %w", err)
		}
	}
	networkv4, err = netip.ParsePrefix(resp.GetNetworkIPv4())
	if err != nil {
		return fmt.Errorf("parse ipv4 network: %w", err)
	}
	addressv6, err = netip.ParsePrefix(resp.GetAddressIPv6())
	if err != nil {
		return fmt.Errorf("parse ipv6 address: %w", err)
	}
	networkv6, err = netip.ParsePrefix(resp.GetNetworkIPv6())
	if err != nil {
		return fmt.Errorf("parse ipv6 network: %w", err)
	}
	startopts := meshnet.StartOptions{
		Key: s.key,
		AddressV4: func() netip.Prefix {
			if !s.opts.DisableIPv4 {
				return addressv4
			}
			return netip.Prefix{}
		}(),
		AddressV6: func() netip.Prefix {
			if !s.opts.DisableIPv6 {
				return addressv6
			}
			return netip.Prefix{}
		}(),
		NetworkV4: networkv4,
		NetworkV6: networkv6,
	}
	log.Debug("Starting network manager", slog.Any("opts", opts))
	err = s.nw.Start(ctx, startopts)
	if err != nil {
		return fmt.Errorf("starting network manager: %w", err)
	}
	for _, peer := range resp.GetPeers() {
		log.Debug("Adding peer", slog.Any("peer", peer))
		err = s.nw.Peers().Add(ctx, peer, resp.GetIceServers())
		if err != nil {
			log.Error("Failed to add peer", slog.String("error", err.Error()))
		}
	}
	if s.opts.UseMeshDNS {
		var servers []netip.AddrPort
		if s.opts.LocalMeshDNSAddr != "" {
			// Use our local port.
			addr, err := netip.ParseAddrPort(s.opts.LocalMeshDNSAddr)
			if err != nil {
				return fmt.Errorf("parsing local dns server: %w", err)
			}
			servers = append(servers, addr)
		} else {
			for _, server := range resp.GetDnsServers() {
				addr, err := netip.ParseAddrPort(server)
				if err != nil {
					return fmt.Errorf("parsing dns server: %w", err)
				}
				servers = append(servers, addr)
			}
		}
		err = s.nw.DNS().AddServers(ctx, servers)
		if err != nil {
			log.Error("Failed to add dns servers", slog.String("error", err.Error()))
		}
	}
	return nil
}

func (s *meshStore) newJoinRequest(opts ConnectOptions, encodedKey string) *v1.JoinRequest {
	if opts.GRPCAdvertisePort <= 0 {
		// Assume the default port.
		opts.GRPCAdvertisePort = services.DefaultGRPCPort
	}
	req := &v1.JoinRequest{
		Id:        s.ID().String(),
		PublicKey: encodedKey,
		PrimaryEndpoint: func() string {
			if opts.PrimaryEndpoint.IsValid() {
				return opts.PrimaryEndpoint.String()
			}
			return ""
		}(),
		WireguardEndpoints: func() []string {
			var eps []string
			for _, ep := range opts.WireGuardEndpoints {
				eps = append(eps, ep.String())
			}
			return eps
		}(),
		ZoneAwarenessID:   s.opts.ZoneAwarenessID,
		AssignIPv4:        !s.opts.DisableIPv4,
		PreferStorageIPv6: !s.opts.DisableIPv6 && opts.PreferIPv6,
		AsVoter:           opts.RequestVote,
		AsObserver:        opts.RequestObserver,
		Routes: func() []string {
			var routes []string
			for _, route := range opts.Routes {
				routes = append(routes, route.String())
			}
			return routes
		}(),
		DirectPeers: opts.DirectPeers,
		Features:    opts.Features,
		Multiaddrs: func() []string {
			var out []string
			for _, addr := range opts.Multiaddrs {
				out = append(out, addr.String())
			}
			return out
		}(),
	}
	return req
}
