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

// Package config contains configuration options for the webmesh libp2p transport
// components.
package config

import (
	"log/slog"

	"github.com/webmeshproj/webmesh/pkg/net/endpoints"
	"github.com/webmeshproj/webmesh/pkg/net/system"
	"github.com/webmeshproj/webmesh/pkg/net/wireguard"
	"github.com/webmeshproj/webmesh/pkg/util/logutil"
)

// Options are the options for the wireguard interface and endpoint
// detection.
type Options struct {
	// Config is the configuration for the WireGuard interface.
	Config WireGuardOptions
	// EndpointDetection are options for doing public endpoint
	// detection for the wireguard interface.
	EndpointDetection *endpoints.DetectOpts
	// Logger is the logger to use for the webmesh transport.
	// If nil, an empty logger will be used.
	Logger *slog.Logger
}

// Default sets default values for any unset options.
func (o *Options) Default() {
	o.Config.Default()
	if o.Logger == nil {
		o.Logger = logutil.NewLogger("")
	}
}

// WireGuardOptions are options for configuring the WireGuard interface on
// the transport.
type WireGuardOptions struct {
	// ListenPort is the port to listen on.
	// If 0, a default port of 51820 will be used.
	ListenPort int
	// InterfaceName is the name of the interface to use.
	// If empty, a default platform dependent name will be used.
	InterfaceName string
	// ForceInterfaceName forces the interface name to be used.
	// If false, the interface name will be changed if it already exists.
	ForceInterfaceName bool
	// MTU is the MTU to use for the interface.
	// If 0, a default MTU of 1420 will be used.
	MTU int
}

func (w *WireGuardOptions) Default() {
	if w.ListenPort == 0 {
		w.ListenPort = wireguard.DefaultListenPort
	}
	if w.InterfaceName == "" {
		w.InterfaceName = wireguard.DefaultInterfaceName
	}
	if w.MTU == 0 {
		w.MTU = system.DefaultMTU
	}
}
