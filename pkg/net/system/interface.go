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

// Package system contains utilities for managing network interfaces on the system.
package system

import (
	"context"
	"errors"
	"net/netip"
)

// ErrRouteExists is returned when a route already exists.
var ErrRouteExists = errors.New("route already exists")

// DefaultMTU is the default MTU for wireguard interfaces.
const DefaultMTU = 1350

// MaxMTU is the maximum MTU for wireguard interfaces.
const MaxMTU = 1500

// Interface represents an underlying machine network interface for
// use with wireguard.
type Interface interface {
	// Name returns the real name of the interface.
	Name() string
	// AddressV4 should return the current private IPv4 address of this interface.
	AddressV4() netip.Prefix
	// AddressV6 should return the current private IPv6 address of this interface.
	AddressV6() netip.Prefix
	// Up activates the interface.
	Up(context.Context) error
	// Down deactivates the interface.
	Down(context.Context) error
	// Destroy destroys the interface.
	Destroy(context.Context) error
	// AddRoute adds a route for the given network.
	AddRoute(context.Context, netip.Prefix) error
	// RemoveRoute removes the route for the given network.
	RemoveRoute(context.Context, netip.Prefix) error
}

// Options represents the options for creating a new interface.
type Options struct {
	// Name is the name of the interface.
	Name string
	// NetworkV4 is the private IPv4 network of this interface.
	NetworkV4 netip.Prefix
	// NetworkV6 is the private IPv6 network of this interface.
	NetworkV6 netip.Prefix
	// DefaultGateway is the default gateway for the interface.
	// If unset, it will be automatically detected from the host.
	DefaultGateway netip.Addr
	// ForceTUN forces the use of a TUN interface.
	ForceTUN bool
	// Modprobe attempts to load the wireguard kernel module.
	Modprobe bool
	// MTU is the MTU of the interface. If unset, it will be automatically
	// detected from the host.
	MTU uint32
}

// IsRouteExists returns true if the given error is a route exists error.
func IsRouteExists(err error) bool {
	return errors.Is(err, ErrRouteExists)
}
