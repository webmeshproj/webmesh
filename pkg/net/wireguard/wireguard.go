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

// Package wireguard contains utilities for working with wireguard interfaces.
package wireguard

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"time"

	v1 "github.com/webmeshproj/api/v1"
	"golang.org/x/exp/slog"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/net/system"
	"github.com/webmeshproj/webmesh/pkg/net/system/link"
	"github.com/webmeshproj/webmesh/pkg/net/system/routes"
)

// DefaultInterfaceName is the default name to use for the WireGuard interface.
var DefaultInterfaceName = "webmesh0"

func init() {
	switch runtime.GOOS {
	case "darwin":
		// macOS TUN interfaces have to be named "utun" followed by a number.
		DefaultInterfaceName = "utun+"
	}
}

// Interface is a high-level interface for managing wireguard connections.
type Interface interface {
	// Interface is the underlying system interface.
	system.Interface

	// Configure configures the wireguard interface to use the given key and listen port.
	Configure(ctx context.Context, key wgtypes.Key, listenPort int) error
	// ListenPort returns the current listen port of the wireguard interface.
	ListenPort() (int, error)
	// PutPeer updates a peer in the wireguard configuration.
	PutPeer(ctx context.Context, peer *Peer) error
	// DeletePeer removes a peer from the wireguard configuration.
	DeletePeer(ctx context.Context, id string) error
	// Peers returns the list of peers in the wireguard configuration.
	Peers() []string
	// Metrics returns the metrics for the wireguard interface and the host.
	Metrics() (*v1.InterfaceMetrics, error)
	// Close closes the wireguard interface and all client connections.
	Close(ctx context.Context) error
}

// Options are options for configuring the wireguard interface.
type Options struct {
	// NodeID is the ID of the node. This is only used for metrics.
	NodeID string
	// ListenPort is the port to listen on.
	ListenPort int
	// Name is the name of the interface.
	Name string
	// ForceName forces the use of the given name by deleting
	// any pre-existing interface with the same name.
	ForceName bool
	// ForceTUN forces the use of a TUN interface.
	ForceTUN bool
	// PersistentKeepAlive is the interval at which to send keepalive packets
	// to peers. If unset, keepalive packets will automatically be sent to publicly
	// accessible peers when this instance is behind a NAT. Otherwise, no keep-alive
	// packets are sent.
	PersistentKeepAlive time.Duration
	// MTU is the MTU to use for the interface.
	MTU int
	// AddressV4 is the private IPv4 address of this interface.
	AddressV4 netip.Prefix
	// AddressV6 is the private IPv6 address of this interface.
	AddressV6 netip.Prefix
	// Metrics is true if prometheus metrics should be enabled.
	Metrics bool
	// MetricsInterval is the interval at which to update metrics.
	// Defaults to 15 seconds.
	MetricsInterval time.Duration
}

type wginterface struct {
	system.Interface
	defaultGateway netip.Addr
	opts           *Options
	cli            *wgctrl.Client
	log            *slog.Logger
	peers          map[string]wgtypes.Key
	peersMux       sync.Mutex
	recorderCancel context.CancelFunc
}

// New creates a new wireguard interface.
func New(ctx context.Context, opts *Options) (Interface, error) {
	log := context.LoggerFrom(ctx).With("component", "wireguard")
	if opts.ForceName {
		log.Info("forcing wireguard interface name", "name", opts.Name)
		iface, err := net.InterfaceByName(opts.Name)
		if err != nil {
			if !system.IsInterfaceNotExists(err) {
				return nil, fmt.Errorf("failed to get interface: %w", err)
			}
		} else if iface != nil {
			err = link.RemoveInterface(ctx, opts.Name)
			if err != nil {
				return nil, fmt.Errorf("failed to delete interface: %w", err)
			}
		}
	}
	if os.Getuid() == 0 {
		log.Debug("enabling ip forwarding")
		err := routes.EnableIPForwarding()
		if err != nil {
			log.Warn("failed to enable ip forwarding", "error", err)
		}
	}
	// Get the default gateway in case we change it later.
	var gw netip.Addr
	var err error
	gw, err = routes.GetDefaultGateway(ctx)
	if err != nil {
		log.Warn("failed to get default gateway", "error", err.Error())
	}
	log.Info("creating wireguard interface", "name", opts.Name)
	iface, err := system.New(ctx, &system.Options{
		Name:      opts.Name,
		NetworkV4: opts.AddressV4,
		NetworkV6: opts.AddressV6,
		ForceTUN:  opts.ForceTUN,
		MTU:       uint32(opts.MTU),
	})
	if err != nil {
		return nil, fmt.Errorf("new interface: %w", err)
	}
	handleErr := func(err error) error {
		if err := iface.Destroy(ctx); err != nil {
			log.Warn("failed to destroy interface", "error", err)
		}
		return err
	}
	cli, err := wgctrl.New()
	if err != nil {
		return nil, handleErr(fmt.Errorf("failed to create wireguard control client: %w", err))
	}
	wg := &wginterface{
		Interface:      iface,
		defaultGateway: gw,
		opts:           opts,
		cli:            cli,
		peers:          make(map[string]wgtypes.Key),
		log:            log,
	}
	if opts.Metrics {
		recorder := NewMetricsRecorder(wg)
		rctx, cancel := context.WithCancel(context.Background())
		wg.recorderCancel = cancel
		if opts.MetricsInterval <= 0 {
			opts.MetricsInterval = 15 * time.Second
		}
		go recorder.Run(rctx, opts.MetricsInterval)
	}
	return wg, nil
}

// ListenPort returns the current listen port of the wireguard interface.
func (w *wginterface) ListenPort() (int, error) {
	iface, err := w.cli.Device(w.opts.Name)
	if err != nil {
		return 0, err
	}
	return iface.ListenPort, nil
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
	if w.recorderCancel != nil {
		w.recorderCancel()
	}
	w.cli.Close()
	return w.Interface.Destroy(ctx)
}

// Configure configures the wireguard interface to use the given key and listen port.
func (w *wginterface) Configure(ctx context.Context, key wgtypes.Key, listenPort int) error {
	err := w.cli.ConfigureDevice(w.Name(), wgtypes.Config{
		PrivateKey:   &key,
		ListenPort:   &listenPort,
		ReplacePeers: false,
	})
	if err != nil {
		return fmt.Errorf("failed to configure wireguard interface: %w", err)
	}
	return nil
}
