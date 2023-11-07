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

package daemoncmd

import (
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/pflag"

	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/logging"
	"github.com/webmeshproj/webmesh/pkg/meshnet/wireguard"
)

// DefaultDaemonSocket returns the default daemon socket path.
func DefaultDaemonSocket() string {
	if runtime.GOOS == "windows" {
		return "\\\\.\\pipe\\webmesh.sock"
	}
	return "/var/run/webmesh/webmesh.sock"
}

// isLocalSocket returns if the address is for a UNIX socket or windows pipe.
func isLocalSocket(addr string) bool {
	if runtime.GOOS == "windows" {
		return strings.HasPrefix(addr, "\\\\")
	}
	return strings.HasPrefix(addr, "/") || strings.HasPrefix(addr, "unix://")
}

// Config is the configuration for the applicaton daeemon.
type Config struct {
	// Enabled is true if the daemon is enabled.
	Enabled bool `koanf:"enabled"`
	// NodeID is the ID to use for mesh connections from this server.
	// If not provided, one will be generated from the key.
	NodeID string `koanf:"node-id"`
	// KeyFile is the path to the WireGuard private key for the node.
	// If set and it does not exist it will be created, otherwise one
	// will be generated.
	KeyFile string `koanf:"key-file,omitempty"`
	// KeyRotation is the duration between key rotations.
	KeyRotation time.Duration `koanf:"key-rotation"`
	// Bind is the bind address for the daemon.
	Bind string `koanf:"bind"`
	// InsecureSocket uses an insecure socket when binding to a unix socket.
	InsecureSocket bool `koanf:"insecure-socket"`
	// GRPCWeb enables gRPC-Web support.
	GRPCWeb bool `koanf:"grpc-web"`
	// CORS are options for configuring CORS. These are only applicable when
	// grpc-web is enabled.
	CORS CORS `koanf:"cors"`
	// UI are options for exposing a gRPC UI.
	UI WebUI `koanf:"ui"`
	// Persistence are options for persisting mesh data.
	Persistence Persistence `koanf:"persistence"`
	// WireGuardStartPort is the starting port for WireGuard connections.
	WireGuardStartPort uint16 `koanf:"wireguard-start-port"`
	// LogLevel is the log level for the daemon.
	LogLevel string `koanf:"log-level"`
	// LogFormat is the log format for the daemon.
	LogFormat string `koanf:"log-format"`
}

// CORS are options for configuring CORS. These are only applicable when
// grpc-web is enabled.
type CORS struct {
	// Enabled is true if CORS is enabled.
	Enabled bool `koanf:"enabled"`
	// AllowedOrigins is a list of allowed origins.
	AllowedOrigins []string `koanf:"allowed-origins"`
}

// WebUI are options for exposing a gRPC UI.
type WebUI struct {
	// Enabled is true if the gRPC UI is enabled.
	Enabled bool `koanf:"enabled"`
	// ListenAddress is the address to listen on.
	ListenAddress string `koanf:"listen-address"`
}

// Persistence is configuration for persistence of mesh connection storage.
type Persistence struct {
	// Path is the root path to store mesh connection data.
	// Each connection will receive its own subdirectory.
	Path string `koanf:"path"`
}

// NewDefaultConfig returns the default configuration.
func NewDefaultConfig() *Config {
	return &Config{
		Enabled:            false,
		NodeID:             "",
		KeyFile:            "",
		KeyRotation:        0,
		Bind:               DefaultDaemonSocket(),
		InsecureSocket:     false,
		GRPCWeb:            false,
		CORS:               CORS{AllowedOrigins: []string{"*"}},
		UI:                 WebUI{Enabled: false, ListenAddress: "127.0.0.1:8080"},
		WireGuardStartPort: wireguard.DefaultListenPort,
		LogLevel:           "info",
		LogFormat:          "json",
	}
}

// NewLogger returns a logger with the given configuration.
func (conf *Config) NewLogger() *slog.Logger {
	return logging.NewLogger(conf.LogLevel, conf.LogFormat)
}

// BindFlags binds the flags to the given flagset.
func (conf *Config) BindFlags(prefix string, flagset *pflag.FlagSet) *Config {
	flagset.BoolVar(&conf.Enabled, prefix+"enabled", conf.Enabled, "Run the node as an application daemon")
	flagset.StringVar(&conf.NodeID, prefix+"node-id", conf.NodeID, "ID to use for mesh connections from this server")
	flagset.StringVar(&conf.KeyFile, prefix+"key-file", conf.KeyFile, "Path to the WireGuard private key for the node")
	flagset.DurationVar(&conf.KeyRotation, prefix+"key-rotation", conf.KeyRotation, "Duration between key rotations")
	flagset.StringVar(&conf.Bind, prefix+"bind", conf.Bind, "Address to bind the application daemon to")
	flagset.BoolVar(&conf.InsecureSocket, prefix+"insecure-socket", conf.InsecureSocket, "Leave default ownership on the Unix socket")
	flagset.BoolVar(&conf.GRPCWeb, prefix+"grpc-web", conf.GRPCWeb, "Use gRPC-Web for the application daemon")
	flagset.Uint16Var(&conf.WireGuardStartPort, prefix+"wireguard-start-port", conf.WireGuardStartPort, "Starting port for WireGuard connections")
	flagset.StringVar(&conf.LogLevel, prefix+"log-level", conf.LogLevel, "Log level for the application daemon")
	flagset.StringVar(&conf.LogFormat, prefix+"log-format", conf.LogFormat, "Log format for the application daemon")
	conf.CORS.BindFlags(prefix+"cors.", flagset)
	conf.UI.BindFlags(prefix+"ui.", flagset)
	conf.Persistence.BindFlags(prefix+"persistence.", flagset)
	return conf
}

// BindFlags binds the CORS flags to the given flagset.
func (conf *CORS) BindFlags(prefix string, flagset *pflag.FlagSet) {
	flagset.BoolVar(&conf.Enabled, prefix+"enabled", conf.Enabled, "Enable CORS")
	flagset.StringSliceVar(&conf.AllowedOrigins, prefix+"allowed-origins", conf.AllowedOrigins, "Allowed origins")
}

// BindFlags binds the UI flags to the given flagset.
func (conf *WebUI) BindFlags(prefix string, flagset *pflag.FlagSet) {
	flagset.BoolVar(&conf.Enabled, prefix+"enabled", conf.Enabled, "Enable the gRPC UI")
	flagset.StringVar(&conf.ListenAddress, prefix+"listen-address", conf.ListenAddress, "Address to listen on for the gRPC UI")
}

// BindFlags binds the persistence flags to the given flagset.
func (conf *Persistence) BindFlags(prefix string, flagset *pflag.FlagSet) {
	flagset.StringVar(&conf.Path, prefix+"path", conf.Path, "Root path to store mesh connection data")
}

// Validate validates the configuration.
func (conf *Config) Validate() error {
	if !conf.Enabled {
		return nil
	}
	if conf.Bind == "" {
		return fmt.Errorf("bind address cannot be empty")
	}
	if conf.UI.Enabled {
		if conf.UI.ListenAddress == "" {
			return fmt.Errorf("ui listen address cannot be empty")
		}
		if isLocalSocket(conf.Bind) {
			return fmt.Errorf("ui cannot be enabled with a file socket")
		}
	}
	return nil
}

// LoadKey loads the wireguard key from the configuration.
func (conf *Config) LoadKey(log *slog.Logger) (crypto.PrivateKey, error) {
	if conf.KeyFile == "" {
		log.Info("Generating ephemeral WireGuard key")
		return crypto.GenerateKey()
	}
	stat, err := os.Stat(conf.KeyFile)
	if err != nil {
		if os.IsNotExist(err) {
			log.Info("Generating new WireGuard key and saving to file", "file", conf.KeyFile)
			key, err := crypto.GenerateKey()
			if err != nil {
				return nil, fmt.Errorf("generate new key: %w", err)
			}
			err = crypto.EncodeKeyToFile(key, conf.KeyFile)
			if err != nil {
				return nil, fmt.Errorf("save key: %w", err)
			}
			return key, nil
		}
		return nil, fmt.Errorf("stat key file: %w", err)
	}
	if stat.IsDir() {
		return nil, fmt.Errorf("key file is a directory")
	}
	if conf.KeyRotation > 0 && stat.ModTime().Add(conf.KeyRotation).Before(time.Now()) {
		log.Info("Removing expired WireGuard key file", "file", conf.KeyFile)
		if err := os.Remove(conf.KeyFile); err != nil {
			return nil, fmt.Errorf("remove expired wireguard key file: %w", err)
		}
		log.Info("Generating new WireGuard key and saving to file", "file", conf.KeyFile)
		key, err := crypto.GenerateKey()
		if err != nil {
			return nil, fmt.Errorf("generate new key: %w", err)
		}
		err = crypto.EncodeKeyToFile(key, conf.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("save key: %w", err)
		}
		return key, nil
	}
	log.Info("Loading WireGuard key from file", "file", conf.KeyFile)
	return crypto.DecodePrivateKeyFromFile(conf.KeyFile)
}
