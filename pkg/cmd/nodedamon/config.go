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
	"runtime"
	"strings"

	"github.com/spf13/pflag"
)

// Config is the configuration for the applicaton daeemon.
type Config struct {
	// Enabled is true if the daemon is enabled.
	Enabled bool `koanf:"enabled"`
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
