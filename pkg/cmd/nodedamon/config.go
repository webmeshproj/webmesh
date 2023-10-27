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

package nodedaemon

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/spf13/pflag"

	"github.com/webmeshproj/webmesh/pkg/crypto"
)

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
	// Bind is the bind address for the daemon.
	Bind string `koanf:"bind"`
	// InsecureSocket uses an insecure socket when binding to a unix socket.
	InsecureSocket bool `koanf:"insecure-socket"`
	// GRPCWeb enables gRPC-Web support.
	GRPCWeb bool `koanf:"grpc-web"`
	// UI are options for exposing a gRPC UI.
	UI WebUI `koanf:"ui"`
	// LogLevel is the log level for the daemon.
	LogLevel string `koanf:"log-level"`
}

// WebUI are options for exposing a gRPC UI.
type WebUI struct {
	// Enabled is true if the gRPC UI is enabled.
	Enabled bool `koanf:"enabled"`
	// ListenAddress is the address to listen on.
	ListenAddress string `koanf:"listen-address"`
}

// NewDefaultConfig returns the default configuration.
func NewDefaultConfig() *Config {
	return &Config{
		Enabled:        false,
		NodeID:         "",
		KeyFile:        "",
		Bind:           DefaultDaemonSocket(),
		InsecureSocket: false,
		GRPCWeb:        false,
		UI:             WebUI{Enabled: false, ListenAddress: "127.0.0.1:8080"},
		LogLevel:       "info",
	}
}

// BindFlags binds the flags to the given flagset.
func (conf *Config) BindFlags(prefix string, flagset *pflag.FlagSet) *Config {
	flagset.BoolVar(&conf.Enabled, prefix+"enabled", conf.Enabled, "Run the node as an application daemon")
	flagset.StringVar(&conf.NodeID, prefix+"node-id", conf.NodeID, "ID to use for mesh connections from this server")
	flagset.StringVar(&conf.KeyFile, prefix+"key-file", conf.KeyFile, "Path to the WireGuard private key for the node")
	flagset.StringVar(&conf.Bind, prefix+"bind", conf.Bind, "Address to bind the application daemon to")
	flagset.BoolVar(&conf.InsecureSocket, prefix+"insecure-socket", conf.InsecureSocket, "Leave default ownership on the Unix socket")
	flagset.BoolVar(&conf.GRPCWeb, prefix+"grpc-web", conf.GRPCWeb, "Use gRPC-Web for the application daemon")
	flagset.StringVar(&conf.LogLevel, prefix+"log-level", conf.LogLevel, "Log level for the application daemon")
	conf.UI.BindFlags(prefix+"ui.", flagset)
	return conf
}

// BindFlags binds the UI flags to the given flagset.
func (conf *WebUI) BindFlags(prefix string, flagset *pflag.FlagSet) {
	flagset.BoolVar(&conf.Enabled, prefix+"enabled", conf.Enabled, "Enable the gRPC UI")
	flagset.StringVar(&conf.ListenAddress, prefix+"listen-address", conf.ListenAddress, "Address to listen on for the gRPC UI")
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
func (conf *Config) LoadKey() (crypto.PrivateKey, error) {
	if conf.KeyFile == "" {
		return crypto.GenerateKey()
	}
	key, err := crypto.DecodePrivateKeyFromFile(conf.KeyFile)
	if err == nil {
		return key, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	key, err = crypto.GenerateKey()
	if err != nil {
		return nil, err
	}
	encoded, err := key.Encode()
	if err != nil {
		return nil, err
	}
	err = os.WriteFile(conf.KeyFile, []byte(encoded), 0600)
	if err != nil {
		return nil, err
	}
	return key, nil
}

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
