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
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/spf13/pflag"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/meshnet/system"
	"github.com/webmeshproj/webmesh/pkg/meshnet/wireguard"
)

// WireGuardOptions are options for configuring the WireGuard interface.
type WireGuardOptions struct {
	// ListenPort is the port to listen on.
	ListenPort int `koanf:"listen-port,omitempty"`
	// Modprobe attempts to load the wireguard kernel module on linux systems.
	Modprobe bool `koanf:"modprobe,omitempty"`
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

	// loaded is an already loaded key from the configuration.
	loaded crypto.PrivateKey `koanf:"-"`
}

// NewWireGuardOptions returns a new WireGuardOptions with sensible defaults.
func NewWireGuardOptions() WireGuardOptions {
	return WireGuardOptions{
		ListenPort:            wireguard.DefaultListenPort,
		Modprobe:              false,
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
	fs.IntVar(&o.ListenPort, prefix+"listen-port", o.ListenPort, "The port to listen on.")
	fs.BoolVar(&o.Modprobe, prefix+"modprobe", o.Modprobe, "Attempt to load the wireguard kernel module on linux systems.")
	fs.StringVar(&o.InterfaceName, prefix+"interface-name", o.InterfaceName, "The name of the interface.")
	fs.BoolVar(&o.ForceInterfaceName, prefix+"force-interface-name", o.ForceInterfaceName, "Force the use of the given name by deleting any pre-existing interface with the same name.")
	fs.BoolVar(&o.ForceTUN, prefix+"force-tun", o.ForceTUN, "Force the use of a TUN interface.")
	fs.BoolVar(&o.Masquerade, prefix+"masquerade", o.Masquerade, "Enable masquerading of traffic from the wireguard interface.")
	fs.DurationVar(&o.PersistentKeepAlive, prefix+"persistent-keepalive", o.PersistentKeepAlive, "The interval at which to send keepalive packets to peers.")
	fs.IntVar(&o.MTU, prefix+"mtu", o.MTU, "The MTU to use for the interface.")
	fs.StringSliceVar(&o.Endpoints, prefix+"endpoints", o.Endpoints, "Additional WireGuard endpoints to broadcast when joining.")
	fs.StringVar(&o.KeyFile, prefix+"key-file", o.KeyFile, "The path to the WireGuard private key. If it does not exist it will be created.")
	fs.DurationVar(&o.KeyRotationInterval, prefix+"key-rotation-interval", o.KeyRotationInterval, "The interval to rotate wireguard keys. Set this to 0 to disable key rotation.")
	fs.BoolVar(&o.RecordMetrics, prefix+"record-metrics", o.RecordMetrics, "Record WireGuard metrics. These are only exposed if the metrics server is enabled.")
	fs.DurationVar(&o.RecordMetricsInterval, prefix+"record-metrics-interval", o.RecordMetricsInterval, "The interval at which to update WireGuard metrics.")
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
		return fmt.Errorf("wireguard.key-rotation-interval must be greater than or equal to 0")
	}
	if o.RecordMetrics {
		if o.RecordMetricsInterval < 0 {
			return fmt.Errorf("wireguard.record-metrics-interval must be greater than 0")
		}
	}
	return nil
}

// LoadKey loads the key from the given configuration.
func (o *WireGuardOptions) LoadKey(ctx context.Context) (crypto.PrivateKey, error) {
	log := context.LoggerFrom(ctx)
	if o.loaded != nil {
		return o.loaded, nil
	}
	if o.KeyFile == "" {
		// Generate an ephemeral key
		log.Debug("Generating ephemeral WireGuard key")
		key, err := crypto.GenerateKey()
		if err != nil {
			return nil, fmt.Errorf("generate ephemeral key: %w", err)
		}
		o.loaded = key
		return key, nil
	}
	// Check that the file exists and hasn't expired.
	stat, err := os.Stat(o.KeyFile)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("stat wireguard key file: %w", err)
	} else if os.IsNotExist(err) {
		// Generate a new key
		log.Debug("Generating new WireGuard key and saving to file", slog.String("file", o.KeyFile))
		key, err := crypto.GenerateKey()
		if err != nil {
			return nil, fmt.Errorf("generate new key: %w", err)
		}
		encoded, err := key.Encode()
		if err != nil {
			return nil, fmt.Errorf("encode key: %w", err)
		}
		if err := os.WriteFile(o.KeyFile, []byte(encoded), 0600); err != nil {
			return nil, fmt.Errorf("write key file: %w", err)
		}
		o.loaded = key
		return key, nil
	}
	if stat.IsDir() {
		return nil, fmt.Errorf("wireguard key file is a directory")
	}
	// Check if the key is expired
	if o.KeyRotationInterval > 0 {
		if stat.ModTime().Add(o.KeyRotationInterval).Before(time.Now()) {
			// Delete the key file if it's older than the key rotation interval.
			log.Debug("Removing expired WireGuard key file", slog.String("file", o.KeyFile))
			if err := os.Remove(o.KeyFile); err != nil {
				return nil, fmt.Errorf("remove expired wireguard key file: %w", err)
			}
			// Generate a new key and save it to the file
			log.Debug("Generating new WireGuard key and saving to file", slog.String("file", o.KeyFile))
			key, err := crypto.GenerateKey()
			if err != nil {
				return nil, fmt.Errorf("generate new key: %w", err)
			}
			encoded, err := key.Encode()
			if err != nil {
				return nil, fmt.Errorf("encode key: %w", err)
			}
			if err := os.WriteFile(o.KeyFile, []byte(encoded), 0600); err != nil {
				return nil, fmt.Errorf("write key file: %w", err)
			}
			o.loaded = key
			return key, nil
		}
	}
	// Load the key from the file
	log.Debug("Loading WireGuard key from file", slog.String("file", o.KeyFile))
	keyData, err := os.ReadFile(o.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	key, err := crypto.DecodePrivateKey(strings.TrimSpace(string(keyData)))
	if err != nil {
		return nil, fmt.Errorf("decode key: %w", err)
	}
	o.loaded = key
	return key, nil
}
