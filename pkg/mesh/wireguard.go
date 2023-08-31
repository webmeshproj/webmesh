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
	"net/netip"
	"os"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/meshdb/peers"
	"github.com/webmeshproj/webmesh/pkg/meshdb/state"
	meshnet "github.com/webmeshproj/webmesh/pkg/net"
	"github.com/webmeshproj/webmesh/pkg/net/mesh"
)

func (s *meshStore) recoverWireguard(ctx context.Context) error {
	if s.testStore {
		return nil
	}
	var meshnetworkv4, meshnetworkv6 netip.Prefix
	var err error
	if !s.opts.DisableIPv6 {
		meshnetworkv6, err = state.New(s.Storage()).GetIPv6Prefix(ctx)
		if err != nil {
			return fmt.Errorf("get ula prefix: %w", err)
		}
	}
	if !s.opts.DisableIPv4 {
		meshnetworkv4, err = state.New(s.Storage()).GetIPv4Prefix(ctx)
		if err != nil {
			return fmt.Errorf("get ipv4 prefix: %w", err)
		}
	}
	p := peers.New(s.Storage())
	self, err := p.Get(ctx, s.ID())
	if err != nil {
		return fmt.Errorf("get self peer: %w", err)
	}
	wireguardKey, err := s.loadWireGuardKey(ctx)
	if err != nil {
		return fmt.Errorf("get current wireguard key: %w", err)
	}
	opts := &meshnet.StartOptions{
		Key: wireguardKey,
		AddressV4: func() netip.Prefix {
			if s.opts.DisableIPv4 {
				return netip.Prefix{}
			}
			return self.PrivateAddrV4()
		}(),
		AddressV6: func() netip.Prefix {
			if s.opts.DisableIPv6 {
				return netip.Prefix{}
			}
			return self.PrivateAddrV6()
		}(),
		NetworkV4: meshnetworkv4,
		NetworkV6: meshnetworkv6,
	}
	err = s.nw.Start(ctx, opts)
	if err != nil {
		return fmt.Errorf("configure wireguard: %w", err)
	}
	wgpeers, err := mesh.WireGuardPeersFor(ctx, s.Storage(), s.ID())
	if err != nil {
		return fmt.Errorf("get wireguard peers: %w", err)
	}
	return s.nw.RefreshPeers(ctx, wgpeers)
}

func (s *meshStore) loadWireGuardKey(ctx context.Context) (wgtypes.Key, error) {
	var key wgtypes.Key
	var err error
	if s.opts.WireGuardKeyFile != "" {
		// Load the key from the specified file.
		stat, err := os.Stat(s.opts.WireGuardKeyFile)
		if err != nil && !os.IsNotExist(err) {
			return key, fmt.Errorf("stat key file: %w", err)
		}
		if err == nil {
			if stat.IsDir() {
				return key, fmt.Errorf("key file is a directory")
			}
			if stat.ModTime().Add(s.opts.KeyRotationInterval).Before(time.Now()) {
				// Delete the key file if it's older than the key rotation interval.
				s.log.Info("Removing expired WireGuard key file", "file", s.opts.WireGuardKeyFile)
				if err := os.Remove(s.opts.WireGuardKeyFile); err != nil {
					return key, fmt.Errorf("remove key file: %w", err)
				}
			} else {
				// If we got here, the key file exists and is not older than the key rotation interval.
				// We'll load the key from the file.
				s.log.Info("Loading WireGuard key from file", "file", s.opts.WireGuardKeyFile)
				keyData, err := os.ReadFile(s.opts.WireGuardKeyFile)
				if err != nil {
					return key, fmt.Errorf("read key file: %w", err)
				}
				return wgtypes.ParseKey(strings.TrimSpace(string(keyData)))
			}
		}
	}
	s.log.Info("Generating new WireGuard key")
	// Generate a new key and save it to the specified file.
	key, err = wgtypes.GeneratePrivateKey()
	if err != nil {
		return key, fmt.Errorf("generate private key: %w", err)
	}
	if s.opts.WireGuardKeyFile != "" {
		s.log.Info("Saving WireGuard key to file", "file", s.opts.WireGuardKeyFile)
		if err := os.WriteFile(s.opts.WireGuardKeyFile, []byte(key.String()+"\n"), 0600); err != nil {
			return key, fmt.Errorf("write key file: %w", err)
		}
	}
	return key, nil
}
