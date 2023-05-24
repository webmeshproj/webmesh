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
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	v1 "gitlab.com/webmesh/api/v1"
	"golang.org/x/exp/slog"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"gitlab.com/webmesh/node/pkg/util"
	"gitlab.com/webmesh/node/pkg/wireguard/system"
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
	DeletePeer(ctx context.Context, peer *Peer) error
	// Peers returns the list of peers in the wireguard configuration.
	Peers() []string
	// IsPublic returns true if this wireguard interface is publicly routable.
	IsPublic() bool
	// Metrics returns the metrics for the wireguard interface and the host.
	Metrics() (*v1.NodeMetrics, error)
	// Close closes the wireguard interface and all client connections.
	Close(ctx context.Context) error
}

// Peer contains configurations for a wireguard peer. When removing,
// only the PublicKey is required.
type Peer struct {
	// ID is the ID of the peer.
	ID string `json:"id"`
	// PublicKey is the public key of the peer.
	PublicKey string `json:"publicKey"`
	// Endpoint is the endpoint of this peer, if applicable.
	Endpoint string `json:"endpoint"`
	// PrivateIPv4 is the private IPv4 address of the peer.
	PrivateIPv4 netip.Prefix `json:"privateIPv4"`
	// PrivateIPv6 is the private IPv6 address of the peer.
	PrivateIPv6 netip.Prefix `json:"privateIPv6"`
}

// IsPubliclyRoutable returns true if the given peer is publicly routable.
func (p *Peer) IsPubliclyRoutable() bool {
	return p.Endpoint != ""
}

// IsRouteExists returns true if the given error is a route exists error.
func IsRouteExists(err error) bool {
	return errors.Is(err, system.ErrRouteExists)
}

type wginterface struct {
	system.Interface
	opts        *Options
	cli         *wgctrl.Client
	log         *slog.Logger
	peerConfigs *peerConfigs
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
	iface, err := system.New(ctx, &system.Options{
		Name:       opts.Name,
		NetworkV4:  opts.NetworkV4,
		NetworkV6:  opts.NetworkV6,
		ForceTUN:   opts.ForceTUN,
		NoModprobe: opts.NoModprobe,
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
		peers:       make(map[string]wgtypes.Key),
		log:         slog.Default().With("component", "wireguard"),
	}, nil
}

// IsPublic returns true if the wireguard interface is publicly accessible.
func (w *wginterface) IsPublic() bool {
	return w.opts.Endpoint != ""
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
