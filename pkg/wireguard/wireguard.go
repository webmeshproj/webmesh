/*
Copyright 2023.

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

// Package wireguard contains utilities for working with wireguard interfaces.
package wireguard

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	v1 "github.com/webmeshproj/api/v1"
	"golang.org/x/exp/slog"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/webmeshproj/node/pkg/util"
	"github.com/webmeshproj/node/pkg/wireguard/system"
)

// Interface is a high-level interface for managing wireguard connections.
type Interface interface {
	// Interface is the underlying system interface.
	system.Interface

	// Configure configures the wireguard interface to use the given key and listen port.
	Configure(ctx context.Context, key wgtypes.Key, listenPort int) error
	// PutPeer updates a peer in the wireguard configuration.
	PutPeer(ctx context.Context, peer *Peer) error
	// DeletePeer removes a peer from the wireguard configuration.
	DeletePeer(ctx context.Context, id string) error
	// Peers returns the list of peers in the wireguard configuration.
	Peers() []string
	// IsPublic returns true if this wireguard interface is publicly routable.
	IsPublic() bool
	// Metrics returns the metrics for the wireguard interface and the host.
	Metrics() (*v1.NodeMetrics, error)
	// Close closes the wireguard interface and all client connections.
	Close(ctx context.Context) error
}

type wginterface struct {
	system.Interface
	opts        *Options
	cli         *wgctrl.Client
	log         *slog.Logger
	peerConfigs *peerConfigs
	epOverrides map[string]netip.AddrPort
	// A map of peer ID's to public keys.
	peers    map[string]wgtypes.Key
	peersMux sync.Mutex
}

// New creates a new wireguard interface.
func New(ctx context.Context, opts *Options) (Interface, error) {
	if opts.ForceName {
		iface, err := net.InterfaceByName(opts.Name)
		if err != nil {
			if _, ok := err.(net.UnknownNetworkError); !ok {
				return nil, fmt.Errorf("failed to get interface: %w", err)
			}
		}
		if iface != nil {
			err = util.RemoveInterface(opts.Name)
			if err != nil {
				return nil, fmt.Errorf("failed to delete interface: %w", err)
			}
		}
	}
	var peerConfigs *peerConfigs
	if opts.AllowedIPs != "" {
		var err error
		peerConfigs, err = parseAllowedIPsMap(opts.AllowedIPs)
		if err != nil {
			return nil, fmt.Errorf("failed to parse allowed IPs: %w", err)
		}
	}
	epOverrides := make(map[string]netip.AddrPort)
	if opts.EndpointOverrides != "" {
		var err error
		epOverrides, err = parseEndpointOverrides(opts.EndpointOverrides)
		if err != nil {
			return nil, fmt.Errorf("failed to parse endpoint overrides: %w", err)
		}
	}
	iface, err := system.New(ctx, &system.Options{
		Name:      opts.Name,
		NetworkV4: opts.NetworkV4,
		NetworkV6: opts.NetworkV6,
		ForceTUN:  opts.ForceTUN,
		Modprobe:  opts.Modprobe,
	})
	if err != nil {
		return nil, err
	}
	cli, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create wireguard control client: %w", err)
	}
	return &wginterface{
		Interface:   iface,
		opts:        opts,
		cli:         cli,
		peerConfigs: peerConfigs,
		epOverrides: epOverrides,
		peers:       make(map[string]wgtypes.Key),
		log:         slog.Default().With("component", "wireguard"),
	}, nil
}

// IsPublic returns true if the wireguard interface is publicly accessible.
func (w *wginterface) IsPublic() bool {
	return w.opts.IsPublic
}

// Peers returns the peers of the wireguard interface.
func (w *wginterface) Peers() []string {
	w.peersMux.Lock()
	defer w.peersMux.Unlock()
	out := make([]string, 0)
	for id := range w.peers {
		out = append(out, id)
	}
	return out
}

// Close closes the wireguard interface.
func (w *wginterface) Close(ctx context.Context) error {
	w.cli.Close()
	return w.Interface.Destroy(ctx)
}

// Configure configures the wireguard interface to use the given key and listen port.
func (w *wginterface) Configure(ctx context.Context, key wgtypes.Key, listenPort int) error {
	err := w.cli.ConfigureDevice(w.Name(), wgtypes.Config{
		PrivateKey:   &key,
		ListenPort:   &listenPort,
		ReplacePeers: false,
		Peers:        nil,
	})
	if err != nil {
		return fmt.Errorf("failed to configure wireguard interface: %w", err)
	}
	return nil
}
