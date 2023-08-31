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

package config

import (
	"fmt"
	"time"

	"github.com/spf13/pflag"

	"github.com/webmeshproj/webmesh/pkg/net/system"
	"github.com/webmeshproj/webmesh/pkg/net/wireguard"
)

// WireGuardOptions are options for configuring the WireGuard interface.
type WireGuardOptions struct {
	// ListenPort is the port to listen on.
	ListenPort int `koanf:"listen-port,omitempty"`
	// InterfaceName is the name of the interface.
	InterfaceName string `koanf:"interface-name,omitempty"`
	// ForceInterfaceName forces the use of the given name by deleting
	// any pre-existing interface with the same name.
	ForceInterfaceName bool `koanf:"force-interface-name,omitempty"`
	// ForceTUN forces the use of a TUN interface.
	ForceTUN bool `koanf:"force-tun,omitempty"`
	// Masquerade enables masquerading of traffic from the wireguard interface.
	Masquerade bool `koanf:"masquerade,omitempty"`
	// PersistentKeepAlive is the interval at which to send keepalive packets
	// to peers. If unset, keepalive packets will automatically be sent to publicly
	// accessible peers when this instance is behind a NAT. Otherwise, no keep-alive
	// packets are sent.
	PersistentKeepAlive time.Duration `koanf:"persistent-keepalive,omitempty"`
	// MTU is the MTU to use for the interface.
	MTU int `koanf:"mtu,omitempty"`
	// Endpoints are additional WireGuard endpoints to broadcast when joining.
	Endpoints []string `koanf:"endpoints,omitempty"`
	// KeyFile is the path to the WireGuard private key. If it does not exist it will be created.
	KeyFile string `koanf:"key-file,omitempty"`
	// KeyRotationInterval is the interval to rotate wireguard keys.
	// Set this to 0 to disable key rotation.
	KeyRotationInterval time.Duration `koanf:"key-rotation-interval,omitempty"`
	// RecordMetrics enables recording of WireGuard metrics. These are only exposed if the
	// metrics server is enabled.
	RecordMetrics bool `koanf:"record-metrics,omitempty"`
	// RecordMetricsInterval is the interval at which to update WireGuard metrics.
	RecordMetricsInterval time.Duration `koanf:"record-metrics-interval,omitempty"`
}

// NewWireGuardOptions returns a new WireGuardOptions with sensible defaults.
func NewWireGuardOptions() WireGuardOptions {
	return WireGuardOptions{
		ListenPort:            wireguard.DefaultListenPort,
		InterfaceName:         wireguard.DefaultInterfaceName,
		ForceInterfaceName:    false,
		ForceTUN:              false,
		Masquerade:            false,
		PersistentKeepAlive:   0,
		MTU:                   system.DefaultMTU,
		Endpoints:             nil,
		KeyFile:               "",
		KeyRotationInterval:   time.Hour * 24 * 7,
		RecordMetrics:         false,
		RecordMetricsInterval: time.Second * 10,
	}
}

// BindFlags binds the flags.
func (o *WireGuardOptions) BindFlags(prefix string, fs *pflag.FlagSet) {
	fs.IntVar(&o.ListenPort, prefix+"wireguard.listen-port", wireguard.DefaultListenPort, "The port to listen on.")
	fs.StringVar(&o.InterfaceName, prefix+"wireguard.interface-name", wireguard.DefaultInterfaceName, "The name of the interface.")
	fs.BoolVar(&o.ForceInterfaceName, prefix+"wireguard.force-interface-name", false, "Force the use of the given name by deleting any pre-existing interface with the same name.")
	fs.BoolVar(&o.ForceTUN, prefix+"wireguard.force-tun", false, "Force the use of a TUN interface.")
	fs.BoolVar(&o.Masquerade, prefix+"wireguard.masquerade", false, "Enable masquerading of traffic from the wireguard interface.")
	fs.DurationVar(&o.PersistentKeepAlive, prefix+"wireguard.persistent-keepalive", 0, "The interval at which to send keepalive packets to peers.")
	fs.IntVar(&o.MTU, prefix+"wireguard.mtu", system.DefaultMTU, "The MTU to use for the interface.")
	fs.StringSliceVar(&o.Endpoints, prefix+"wireguard.endpoints", nil, "Additional WireGuard endpoints to broadcast when joining.")
	fs.StringVar(&o.KeyFile, prefix+"wireguard.key-file", "", "The path to the WireGuard private key. If it does not exist it will be created.")
	fs.DurationVar(&o.KeyRotationInterval, prefix+"wireguard.key-rotation-interval", time.Hour*24*7, "The interval to rotate wireguard keys. Set this to 0 to disable key rotation.")
	fs.BoolVar(&o.RecordMetrics, prefix+"wireguard.record-metrics", false, "Record WireGuard metrics. These are only exposed if the metrics server is enabled.")
	fs.DurationVar(&o.RecordMetricsInterval, prefix+"wireguard.record-metrics-interval", time.Second*10, "The interval at which to update WireGuard metrics.")
}

// Validate validates the options.
func (o *WireGuardOptions) Validate() error {
	if o.ListenPort <= 1024 {
		return fmt.Errorf("wireguard.listen-port must be greater than 1024")
	}
	if o.InterfaceName == "" {
		return fmt.Errorf("wireguard.interface-name must be set")
	}
	if o.MTU < 1280 {
		return fmt.Errorf("wireguard.mtu must be greater than 1280")
	}
	if o.KeyRotationInterval < 0 {
		return fmt.Errorf("wireguard.key-rotation-interval must be greater than 0")
	}
	if o.RecordMetrics {
		if o.RecordMetricsInterval < 0 {
			return fmt.Errorf("wireguard.record-metrics-interval must be greater than 0")
		}
	}
	return nil
}
