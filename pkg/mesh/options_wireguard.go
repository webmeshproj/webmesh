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
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/webmeshproj/webmesh/pkg/net/system"
	"github.com/webmeshproj/webmesh/pkg/net/wireguard"
	"github.com/webmeshproj/webmesh/pkg/util"
)

const (
	WireguardListenPortEnvVar            = "WIREGUARD_LISTEN_PORT"
	WireguardNameEnvVar                  = "WIREGUARD_INTERFACE_NAME"
	WireguardForceNameEnvVar             = "WIREGUARD_FORCE_INTERFACE_NAME"
	WireguardForceTUNEnvVar              = "WIREGUARD_FORCE_TUN"
	WireguardModprobeEnvVar              = "WIREGUARD_MODPROBE"
	WireguardMasqueradeEnvVar            = "WIREGUARD_MASQUERADE"
	WireguardAllowedIPsEnvVar            = "WIREGUARD_ALLOWED_IPS"
	WireguardPersistentKeepaliveEnvVar   = "WIREGUARD_PERSISTENT_KEEPALIVE"
	WireguardMTUEnvVar                   = "WIREGUARD_MTU"
	WireGuardEndpointsEnvVar             = "WIREGUARD_ENDPOINTS"
	WireGuardKeyFileEnvVar               = "WIREGUARD_KEY_FILE"
	WireGuardKeyRotationIntervalEnvVar   = "WIREGUARD_KEY_ROTATION_INTERVAL"
	WireGuardRecordMetricsEnvVar         = "WIREGUARD_RECORD_METRICS"
	WireGuardRecordMetricsIntervalEnvVar = "WIREGUARD_RECORD_METRICS_INTERVAL"
)

// WireGuardOptions are options for configuring the WireGuard interface.
type WireGuardOptions struct {
	// ListenPort is the port to listen on.
	ListenPort int `yaml:"listen-port,omitempty" json:"listen-port,omitempty" toml:"listen-port,omitempty" mapstructure:"listen-port,omitempty"`
	// InterfaceName is the name of the interface.
	InterfaceName string `yaml:"interface-name,omitempty" json:"interface-name,omitempty" toml:"interface-name,omitempty" mapstructure:"interface-name,omitempty"`
	// ForceInterfaceName forces the use of the given name by deleting
	// any pre-existing interface with the same name.
	ForceInterfaceName bool `yaml:"force-interface-name,omitempty" json:"force-interface-name,omitempty" toml:"force-interface-name,omitempty" mapstructure:"force-interface-name,omitempty"`
	// ForceTUN forces the use of a TUN interface.
	ForceTUN bool `yaml:"force-tun,omitempty" json:"force-tun,omitempty" toml:"force-tun,omitempty" mapstructure:"force-tun,omitempty"`
	// Modprobe attempts to probe the wireguard module.
	Modprobe bool `yaml:"modprobe,omitempty" json:"modprobe,omitempty" toml:"modprobe,omitempty" mapstructure:"modprobe,omitempty"`
	// Masquerade enables masquerading of traffic from the wireguard interface.
	Masquerade bool `yaml:"masquerade,omitempty" json:"masquerade,omitempty" toml:"masquerade,omitempty" mapstructure:"masquerade,omitempty"`
	// PersistentKeepAlive is the interval at which to send keepalive packets
	// to peers. If unset, keepalive packets will automatically be sent to publicly
	// accessible peers when this instance is behind a NAT. Otherwise, no keep-alive
	// packets are sent.
	PersistentKeepAlive time.Duration `yaml:"persistent-keepalive,omitempty" json:"persistent-keepalive,omitempty" toml:"persistent-keepalive,omitempty" mapstructure:"persistent-keepalive,omitempty"`
	// MTU is the MTU to use for the interface.
	MTU int `yaml:"mtu,omitempty" json:"mtu,omitempty" toml:"mtu,omitempty" mapstructure:"mtu,omitempty"`
	// Endpoints are additional WireGuard endpoints to broadcast when joining.
	Endpoints []string `json:"endpoints,omitempty" yaml:"endpoints,omitempty" toml:"endpoints,omitempty" mapstructure:"endpoints,omitempty"`
	// KeyFile is the path to the WireGuard private key. If it does not exist it will be created.
	KeyFile string `json:"key-file,omitempty" yaml:"key-file,omitempty" toml:"key-file,omitempty" mapstructure:"key-file,omitempty"`
	// KeyRotationInterval is the interval to rotate wireguard keys.
	// Set this to 0 to disable key rotation.
	KeyRotationInterval time.Duration `json:"key-rotation-interval,omitempty" yaml:"key-rotation-interval,omitempty" toml:"key-rotation-interval,omitempty" mapstructure:"key-rotation-interval,omitempty"`
	// RecordMetrics enables recording of WireGuard metrics. These are only exposed if the
	// metrics server is enabled.
	RecordMetrics bool `json:"record-metrics,omitempty" yaml:"record-metrics,omitempty" toml:"record-metrics,omitempty" mapstructure:"record-metrics,omitempty"`
	// RecordMetricsInterval is the interval at which to update WireGuard metrics.
	RecordMetricsInterval time.Duration `json:"record-metrics-interval,omitempty" yaml:"record-metrics-interval,omitempty" toml:"record-metrics-interval,omitempty" mapstructure:"record-metrics-interval,omitempty"`
}

// WireGuardOptions returns a new WireGuardOptions with sensible defaults.
// If name or port are empty, default are used.
func NewWireGuardOptions(name string, port int) *WireGuardOptions {
	if name == "" {
		name = wireguard.DefaultInterfaceName
	}
	if port == 0 {
		port = wireguard.DefaultListenPort
	}
	return &WireGuardOptions{
		ListenPort:            port,
		InterfaceName:         name,
		MTU:                   system.DefaultMTU,
		KeyRotationInterval:   time.Hour * 24 * 7,
		RecordMetrics:         false,
		RecordMetricsInterval: time.Second * 15,
		Endpoints: func() []string {
			if val, ok := os.LookupEnv(WireGuardEndpointsEnvVar); ok {
				return strings.Split(val, ",")
			}
			return nil
		}(),
	}
}

// BindFlags binds the options to the given flag set.
func (o *WireGuardOptions) BindFlags(fl *flag.FlagSet, defaultIfaceName string, prefix ...string) {
	var p string
	if len(prefix) > 0 {
		p = strings.Join(prefix, ".") + "."
	}
	fl.IntVar(&o.ListenPort, p+"wireguard.listen-port", util.GetEnvIntDefault(WireguardListenPortEnvVar, 51820),
		"The WireGuard listen port.")
	fl.StringVar(&o.InterfaceName, p+"wireguard.interface-name", util.GetEnvDefault(WireguardNameEnvVar, defaultIfaceName),
		"The WireGuard interface name.")
	fl.BoolVar(&o.ForceInterfaceName, p+"wireguard.force-interface-name", util.GetEnvDefault(WireguardForceNameEnvVar, "false") == "true",
		"Force the use of the given name by deleting any pre-existing interface with the same name.")
	fl.BoolVar(&o.ForceTUN, p+"wireguard.force-tun", util.GetEnvDefault(WireguardForceTUNEnvVar, "false") == "true",
		"Force the use of a TUN interface.")
	fl.BoolVar(&o.Modprobe, p+"wireguard.modprobe", util.GetEnvDefault(WireguardModprobeEnvVar, "false") == "true",
		"Attempt to load the WireGuard kernel module.")
	fl.BoolVar(&o.Masquerade, p+"wireguard.masquerade", util.GetEnvDefault(WireguardMasqueradeEnvVar, "false") == "true",
		"Masquerade traffic from the WireGuard interface.")
	fl.DurationVar(&o.PersistentKeepAlive, p+"wireguard.persistent-keepalive", util.GetEnvDurationDefault(WireguardPersistentKeepaliveEnvVar, 0),
		`PersistentKeepAlive is the interval at which to send keepalive packets
to peers. If unset, keepalive packets will automatically be sent to publicly
accessible peers when this instance is behind a NAT. Otherwise, no keep-alive
packets are sent.`)
	fl.IntVar(&o.MTU, p+"wireguard.mtu", util.GetEnvIntDefault(WireguardMTUEnvVar, system.DefaultMTU),
		"The MTU to use for the interface.")
	fl.Func(p+"wireguard.endpoints", `Comma separated list of additional WireGuard endpoints to broadcast when joining a cluster.`, func(s string) error {
		o.Endpoints = strings.Split(s, ",")
		return nil
	})
	fl.StringVar(&o.KeyFile, p+"wireguard.key-file", util.GetEnvDefault(WireGuardKeyFileEnvVar, ""),
		"The path to the WireGuard private key. If it does not exist it will be created.")
	fl.DurationVar(&o.KeyRotationInterval, p+"wireguard.key-rotation-interval", util.GetEnvDurationDefault(WireGuardKeyRotationIntervalEnvVar, time.Hour*24*7),
		"Interval to rotate WireGuard keys. Set this to 0 to disable key rotation.")
	fl.BoolVar(&o.RecordMetrics, p+"wireguard.record-metrics", util.GetEnvDefault(WireGuardRecordMetricsEnvVar, "false") == "true",
		"Publish WireGuard metrics.")
	fl.DurationVar(&o.RecordMetricsInterval, p+"wireguard.record-metrics-interval", util.GetEnvDurationDefault(WireGuardRecordMetricsIntervalEnvVar, time.Second*15),
		"Interval at which to update WireGuard metrics.")
}

// Validate validates the options.
func (o *WireGuardOptions) Validate() error {
	if o == nil {
		return errors.New("wireguard configuration cannot be empty")
	}
	if o.ListenPort <= 1024 {
		return errors.New("wireguard.listen-port must be greater than 1024")
	}
	if o.PersistentKeepAlive < 0 {
		return errors.New("wireguard.persistent-keepalive must not be negative")
	}
	if o.MTU < 0 {
		return errors.New("wireguard.mtu must not be negative")
	} else if o.MTU > system.MaxMTU {
		return fmt.Errorf("wireguard.mtu must not be greater than %d", system.MaxMTU)
	}
	if o.KeyRotationInterval < 0 {
		return errors.New("key rotation interval must be >= 0")
	}
	if o.RecordMetrics && o.RecordMetricsInterval < 0 {
		return errors.New("publish metrics interval must be >= 0")
	}
	return nil
}
