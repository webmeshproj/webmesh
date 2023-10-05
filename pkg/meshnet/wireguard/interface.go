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
	"log/slog"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	v1 "github.com/webmeshproj/api/v1"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/meshnet/system"
	"github.com/webmeshproj/webmesh/pkg/meshnet/system/link"
	"github.com/webmeshproj/webmesh/pkg/meshnet/system/routes"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

// DefaultListenPort is the default listen port for the WireGuard interface.
const DefaultListenPort = 51820

// DefaultInterfaceName is the default name to use for the WireGuard interface.
var DefaultInterfaceName = "webmesh+"

func init() {
	switch runtime.GOOS {
	case "darwin":
		// macOS TUN interfaces have to be named "utun" followed by a number.
		DefaultInterfaceName = "utun0"
	}
}

// Interface is a high-level interface for managing wireguard connections.
type Interface interface {
	// Interface is the underlying system interface.
	system.Interface

	// Configure configures the wireguard interface to use the given key and listen port.
	Configure(ctx context.Context, key crypto.PrivateKey) error
	// ListenPort returns the current listen port of the wireguard interface.
	ListenPort() (int, error)
	// PutPeer updates a peer in the wireguard configuration.
	PutPeer(ctx context.Context, peer *Peer) error
	// DeletePeer removes a peer from the wireguard configuration.
	DeletePeer(ctx context.Context, id string) error
	// Peers returns the list of peers in the wireguard configuration.
	Peers() map[string]Peer
	// Metrics returns the metrics for the wireguard interface and the host.
	Metrics() (*v1.InterfaceMetrics, error)
	// Close closes the wireguard interface and all client connections.
	Close(ctx context.Context) error
}

// Options are options for configuring the wireguard interface.
type Options struct {
	// NodeID is the ID of the node. This is only used for metrics.
	NodeID types.NodeID
	// ListenPort is the port to listen on.
	ListenPort int
	// NetNs is the network namespace to use for the interface.
	// This is only used on Linux.
	NetNs string
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
	// NetworkV4 is the IPv4 network of this interface.
	NetworkV4 netip.Prefix
	// NetworkV6 is the IPv6 network of this interface.
	NetworkV6 netip.Prefix
	// Metrics is true if prometheus metrics should be enabled.
	Metrics bool
	// MetricsInterval is the interval at which to update metrics.
	// Defaults to 15 seconds.
	MetricsInterval time.Duration
	// DisableIPv4 disables IPv4 on the interface.
	DisableIPv4 bool
	// DisableIPv6 disables IPv6 on the interface.
	DisableIPv6 bool
}

type wginterface struct {
	system.Interface
	defaultGateway routes.Gateway
	changedGateway bool
	opts           *Options
	log            *slog.Logger
	peers          map[string]Peer
	peersMux       sync.Mutex
	recorderCancel context.CancelFunc
}

// New creates a new wireguard interface.
func New(ctx context.Context, opts *Options) (Interface, error) {
	log := context.LoggerFrom(ctx).With("component", "wireguard")
	if opts.Name == "" {
		opts.Name = DefaultInterfaceName
	}
	if opts.MTU <= 0 {
		opts.MTU = system.DefaultMTU
	}
	if opts.ForceName {
		if !strings.HasSuffix(opts.Name, "+") {
			log.Warn("Forcing wireguard interface name", "name", opts.Name)
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
	}
	if os.Getuid() == 0 {
		log.Debug("Enabling ip forwarding")
		err := routes.EnableIPForwarding()
		if err != nil {
			log.Debug("Failed to enable ip forwarding", "error", err.Error())
		}
	}
	// Get the default gateway in case we change it later.
	var gw routes.Gateway
	var err error
	gw, err = routes.GetDefaultGateway(ctx)
	if err != nil {
		log.Warn("failed to get default gateway", "error", err.Error())
	}
	log.Info("Creating wireguard interface", "name", opts.Name)
	ifaceopts := &system.Options{
		Name:        opts.Name,
		NetNs:       opts.NetNs,
		AddressV4:   opts.AddressV4,
		AddressV6:   opts.AddressV6,
		ForceTUN:    opts.ForceTUN,
		MTU:         uint32(opts.MTU),
		DisableIPv4: opts.DisableIPv4,
		DisableIPv6: opts.DisableIPv6,
	}
	log.Debug("Creating system interface", "options", ifaceopts)
	iface, err := system.New(ctx, ifaceopts)
	if err != nil {
		return nil, fmt.Errorf("new system interface: %w", err)
	}
	opts.Name = iface.Name()
	wg := &wginterface{
		Interface:      iface,
		defaultGateway: gw,
		opts:           opts,
		peers:          make(map[string]Peer),
		log:            log,
	}
	if opts.Metrics {
		recorder := NewMetricsRecorder(ctx, wg)
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
	if runtime.GOOS == "linux" && w.opts.NetNs != "" {
		var listenPort int
		var err error
		err = system.DoInNetNS(w.opts.NetNs, func() error {
			listenPort, err = w.getListenPort()
			return err
		})
		return listenPort, err
	}
	return w.getListenPort()
}

func (w *wginterface) getListenPort() (int, error) {
	cli, err := wgctrl.New()
	if err != nil {
		return 0, err
	}
	iface, err := cli.Device(w.Name())
	if err != nil {
		return 0, err
	}
	return iface.ListenPort, nil
}

// Peers returns the peers of the wireguard interface.
func (w *wginterface) Peers() map[string]Peer {
	w.peersMux.Lock()
	defer w.peersMux.Unlock()
	// Copy the map
	out := make(map[string]Peer)
	for id, peer := range w.peers {
		p := peer
		out[id] = p
	}
	return out
}

// Close closes the wireguard interface.
func (w *wginterface) Close(ctx context.Context) error {
	if w.recorderCancel != nil {
		w.recorderCancel()
	}
	if w.changedGateway {
		defer func() {
			var err error
			if w.opts.NetNs != "" {
				err = system.DoInNetNS(w.opts.NetNs, func() error {
					return routes.SetDefaultIPv4Gateway(ctx, w.defaultGateway)
				})
			} else {
				err = routes.SetDefaultIPv4Gateway(ctx, w.defaultGateway)
			}
			if err != nil {
				w.log.Warn("Failed to reset default gateway", "error", err.Error())
			}
		}()
	}
	return w.Interface.Destroy(ctx)
}

// Configure configures the wireguard interface to use the given key and listen port.
func (w *wginterface) Configure(ctx context.Context, key crypto.PrivateKey) error {
	if runtime.GOOS == "linux" && w.opts.NetNs != "" {
		return system.DoInNetNS(w.opts.NetNs, func() error {
			return w.configure(ctx, key)
		})
	}
	return w.configure(ctx, key)
}

func (w *wginterface) configure(ctx context.Context, key crypto.PrivateKey) error {
	cli, err := wgctrl.New()
	if err != nil {
		return err
	}
	var listenPort *int
	if w.opts.ListenPort != 0 {
		listenPort = &w.opts.ListenPort
	}
	wgKey := key.WireGuardKey()
	err = cli.ConfigureDevice(w.Name(), wgtypes.Config{
		PrivateKey:   &wgKey,
		ListenPort:   listenPort,
		ReplacePeers: false,
	})
	if err != nil {
		return fmt.Errorf("failed to configure wireguard interface: %w", err)
	}
	return nil
}

// Metrics returns the metrics for the wireguard interface.
func (w *wginterface) Metrics() (*v1.InterfaceMetrics, error) {
	var metrics *v1.InterfaceMetrics
	if runtime.GOOS == "linux" && w.opts.NetNs != "" {
		var err error
		err = system.DoInNetNS(w.opts.NetNs, func() error {
			metrics, err = w.getMetrics()
			return err
		})
		if err != nil {
			return nil, err
		}
		return metrics, nil
	}
	return w.getMetrics()
}

func (w *wginterface) getMetrics() (*v1.InterfaceMetrics, error) {
	cli, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	device, err := cli.Device(w.Name())
	if err != nil {
		return nil, err
	}
	metrics := &v1.InterfaceMetrics{
		DeviceName:         device.Name,
		PublicKey:          device.PublicKey.String(),
		AddressV4:          w.Interface.AddressV4().String(),
		AddressV6:          w.Interface.AddressV6().String(),
		Type:               device.Type.String(),
		ListenPort:         int32(device.ListenPort),
		TotalReceiveBytes:  0,
		TotalTransmitBytes: 0,
		NumPeers:           int32(len(device.Peers)),
		Peers:              make([]*v1.PeerMetrics, len(device.Peers)),
	}
	for i, peer := range device.Peers {
		metrics.TotalReceiveBytes += uint64(peer.ReceiveBytes)
		metrics.TotalTransmitBytes += uint64(peer.TransmitBytes)
		metrics.Peers[i] = &v1.PeerMetrics{
			PublicKey:           peer.PublicKey.String(),
			Endpoint:            peer.Endpoint.String(),
			PersistentKeepAlive: peer.PersistentKeepaliveInterval.String(),
			LastHandshakeTime:   peer.LastHandshakeTime.UTC().Format(time.RFC3339),
			AllowedIPs: func() []string {
				var ips []string
				for _, ip := range peer.AllowedIPs {
					ips = append(ips, ip.String())
				}
				return ips
			}(),
			ProtocolVersion: int64(peer.ProtocolVersion),
			ReceiveBytes:    uint64(peer.ReceiveBytes),
			TransmitBytes:   uint64(peer.TransmitBytes),
		}
	}
	return metrics, nil
}
