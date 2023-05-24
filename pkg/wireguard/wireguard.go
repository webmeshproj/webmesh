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
	"time"

	"github.com/elastic/go-sysinfo"
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
	// AllowedIPs is the list of allowed IPs for the peer, if applicable.
	AllowedIPs []string `json:"allowedIPs"`
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
	opts *Options
	cli  *wgctrl.Client
	log  *slog.Logger
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
		Interface: iface,
		opts:      opts,
		cli:       cli,
		peers:     make(map[string]wgtypes.Key),
		log:       slog.Default().With("component", "wireguard"),
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

// PutPeer updates a peer in the wireguard configuration.
func (w *wginterface) PutPeer(ctx context.Context, peer *Peer) error {
	w.peersMux.Lock()
	defer w.peersMux.Unlock()
	w.log.Debug("put peer", slog.Any("peer", peer))
	key, err := wgtypes.ParseKey(peer.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}
	var keepAlive *time.Duration
	var endpoint *net.UDPAddr
	var allowedIPs []net.IPNet
	if peer.PrivateIPv6.IsValid() {
		allowedIPs = append(allowedIPs, net.IPNet{
			IP:   peer.PrivateIPv6.Addr().AsSlice(),
			Mask: net.CIDRMask(peer.PrivateIPv6.Bits(), 128),
		})
	}
	if peer.PrivateIPv4.IsValid() {
		// TODO: We force this to 32 for now, but we should make this configurable
		allowedIPs = append(allowedIPs, net.IPNet{
			IP:   peer.PrivateIPv4.Addr().AsSlice(),
			Mask: net.CIDRMask(32, 32),
		})
	}
	for _, ip := range peer.AllowedIPs {
		_, net, err := net.ParseCIDR(ip)
		if err != nil {
			return fmt.Errorf("failed to parse allowed IP: %w", err)
		}
		allowedIPs = append(allowedIPs, *net)
	}
	if peer.IsPubliclyRoutable() {
		// The peer is publicly accessible
		udpAddr, err := net.ResolveUDPAddr("udp", peer.Endpoint)
		if err != nil {
			return fmt.Errorf("failed to resolve peer endpoint: %w", err)
		}
		endpoint = udpAddr
		if !w.IsPublic() {
			// We are behind a NAT and the peer isn't.
			// Allow all network traffic to the peer.
			// TODO: Make this configurable
			if w.opts.NetworkV6.IsValid() {
				allowedIPs = append(allowedIPs, net.IPNet{
					IP:   w.opts.NetworkV6.Addr().AsSlice(),
					Mask: net.CIDRMask(w.opts.NetworkV6.Bits(), 128),
				})
			}
			if w.opts.NetworkV4.IsValid() {
				allowedIPs = append(allowedIPs, net.IPNet{
					IP:   w.opts.NetworkV4.Addr().AsSlice(),
					Mask: net.CIDRMask(w.opts.NetworkV4.Bits(), 32),
				})
			}
			// Set the keepalive interval to 25 seconds
			// TODO: Make this configurable
			keepAlive = new(time.Duration)
			*keepAlive = 25 * time.Second
		}
	} else if !w.IsPublic() {
		// We are behind a NAT and the peer is too.
		// No reason to track them
		return nil
	} else { // nolint:staticcheck
		// We are publicly accessible and the peer isn't.
		// We allow their private addresses to be routed to us (above).
		// TODO: Make this configurable
	}
	w.log.Debug("computed allowed IPs for peer",
		slog.String("peer-id", peer.ID),
		slog.Any("allowed-ips", allowedIPs))
	peerCfg := wgtypes.PeerConfig{
		PublicKey:                   key,
		UpdateOnly:                  false,
		ReplaceAllowedIPs:           true,
		Endpoint:                    endpoint,
		AllowedIPs:                  allowedIPs,
		PersistentKeepaliveInterval: keepAlive,
	}
	w.log.Debug("configuring peer", slog.Any("peer", peerCfg))
	err = w.cli.ConfigureDevice(w.Name(), wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerCfg},
	})
	if err != nil {
		return fmt.Errorf("failed to configure wireguard interface: %w", err)
	}
	// Add the peer to our map
	w.peers[peer.ID] = key
	// Add routes to the allowed IPs
	for _, ip := range allowedIPs {
		addr, _ := netip.AddrFromSlice(ip.IP)
		_, bits := ip.Mask.Size()
		prefix := netip.PrefixFrom(addr, bits)
		if prefix.Addr().Is6() && w.opts.NetworkV6.IsValid() {
			err = w.AddRoute(ctx, prefix)
			if err != nil && !IsRouteExists(err) {
				return fmt.Errorf("failed to add route: %w", err)
			}
		}
		if prefix.Addr().Is4() && w.opts.NetworkV4.IsValid() {
			err = w.AddRoute(ctx, prefix)
			if err != nil && !IsRouteExists(err) {
				return fmt.Errorf("failed to add route: %w", err)
			}
		}
	}
	return nil
}

// DeletePeer removes a peer from the wireguard configuration.
func (w *wginterface) DeletePeer(ctx context.Context, peer *Peer) error {
	w.peersMux.Lock()
	defer w.peersMux.Unlock()
	if key, ok := w.peers[peer.ID]; ok {
		delete(w.peers, peer.ID)
		return w.cli.ConfigureDevice(w.Name(), wgtypes.Config{
			Peers: []wgtypes.PeerConfig{
				{
					PublicKey: key,
					Remove:    true,
				},
			},
		})
	}
	return nil
}

// Metrics returns the metrics for the wireguard interface and the host.
func (w *wginterface) Metrics() (*v1.NodeMetrics, error) {
	device, err := w.cli.Device(w.Name())
	if err != nil {
		return nil, err
	}
	metrics := &v1.NodeMetrics{
		DeviceName:         device.Name,
		PublicKey:          device.PublicKey.String(),
		AddressV4:          w.Interface.AddressV4().String(),
		AddressV6:          w.Interface.AddressV6().String(),
		Type:               device.Type.String(),
		ListenPort:         int32(device.ListenPort),
		TotalReceiveBytes:  0,
		TotalTransmitBytes: 0,
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
			AllowedIps: func() []string {
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
	host, err := sysinfo.Host()
	if err != nil {
		w.log.Error("failed to get host info", slog.String("error", err.Error()))
		return metrics, nil
	}
	info := host.Info()
	// Build out base system info
	metrics.System = &v1.HostMetrics{
		Cpu:    &v1.CPUTimes{},
		Memory: &v1.MemoryInfo{},
		Host: &v1.HostInfo{
			Architecture: info.Architecture,
			BootTime:     info.BootTime.UTC().Format(time.RFC3339),
			Containerized: func() bool {
				if info.Containerized != nil {
					return *info.Containerized
				}
				return false
			}(),
			Hostname:      info.Hostname,
			Ips:           info.IPs,
			KernelVersion: info.KernelVersion,
			Macs:          info.MACs,
			Os: &v1.OSInfo{
				Type:     info.OS.Type,
				Family:   info.OS.Family,
				Platform: info.OS.Platform,
				Name:     info.OS.Name,
				Version:  info.OS.Version,
				Major:    int64(info.OS.Major),
				Minor:    int64(info.OS.Minor),
				Patch:    int64(info.OS.Patch),
				Build:    info.OS.Build,
				Codename: info.OS.Codename,
			},
			Timezone: info.Timezone,
			Uptime:   info.Uptime().String(),
		},
	}
	// CPU and load average
	cpuTimes, err := host.CPUTime()
	if err != nil {
		w.log.Error("failed to get cpu times", slog.String("error", err.Error()))
	} else {
		metrics.System.Cpu = &v1.CPUTimes{
			User:    cpuTimes.User.String(),
			System:  cpuTimes.System.String(),
			Idle:    cpuTimes.Idle.String(),
			IoWait:  cpuTimes.IOWait.String(),
			Irq:     cpuTimes.IRQ.String(),
			Nice:    cpuTimes.Nice.String(),
			SoftIrq: cpuTimes.SoftIRQ.String(),
			Steal:   cpuTimes.Steal.String(),
		}
	}
	loadAverage, err := util.LoadAverage()
	if err != nil {
		w.log.Error("failed to get load average", slog.String("error", err.Error()))
	} else {
		metrics.System.Cpu.LoadAverage = loadAverage
	}
	// Memory usage
	mem, err := host.Memory()
	if err != nil {
		w.log.Error("failed to get memory info", slog.String("error", err.Error()))
		return metrics, nil
	}
	metrics.System.Memory = &v1.MemoryInfo{
		Total:        mem.Total,
		Used:         mem.Used,
		Available:    mem.Available,
		Free:         mem.Free,
		VirtualTotal: mem.VirtualTotal,
		VirtualUsed:  mem.VirtualUsed,
		VirtualFree:  mem.VirtualFree,
	}
	// Disk usage
	mounts, err := util.MountPaths()
	if err != nil {
		w.log.Error("failed to get mount paths", slog.String("error", err.Error()))
		return metrics, nil
	}
	metrics.System.Disks = make([]*v1.DiskInfo, 0)
	for path, device := range mounts {
		diskMetrics, err := util.DiskUsage(path)
		if err != nil {
			w.log.Error("failed to get disk usage", slog.String("error", err.Error()))
			continue
		}
		diskMetrics.Device = device
		metrics.System.Disks = append(metrics.System.Disks, diskMetrics)
	}
	return metrics, nil
}
