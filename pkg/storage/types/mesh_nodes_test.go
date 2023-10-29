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

package types

import (
	"net/netip"
	"testing"

	v1 "github.com/webmeshproj/api/go/v1"
)

func TestMeshNodeWrapper(t *testing.T) {
	t.Parallel()

	t.Run("NodeHasFeature", func(t *testing.T) {
		t.Parallel()
		node := MeshNode{&v1.MeshNode{}}
		if node.HasFeature(1) {
			t.Errorf("expected node to not have feature 0")
		}
		node.Features = append(node.Features, &v1.FeaturePort{
			Feature: 1,
			Port:    1,
		})
		if !node.HasFeature(1) {
			t.Errorf("expected node to have feature 1")
		}
	})

	t.Run("NodePortForFeature", func(t *testing.T) {
		t.Parallel()
		node := MeshNode{&v1.MeshNode{}}
		// Features should always return 0 when not found.
		if port := node.PortFor(1); port != 0 {
			t.Errorf("expected port for feature 1 to be 0, got %d", port)
		}
		node.Features = append(node.Features, &v1.FeaturePort{
			Feature: 1,
			Port:    1,
		})
		if port := node.PortFor(1); port != 1 {
			t.Errorf("expected port for feature 1 to be 1, got %d", port)
		}
	})

	t.Run("NodeRPCPort", func(t *testing.T) {
		t.Parallel()
		node := MeshNode{&v1.MeshNode{}}
		// Features should always return 0 when not found.
		if port := node.RPCPort(); port != 0 {
			t.Errorf("expected port for feature NODES to be 0, got %d", port)
		}
		node.Features = append(node.Features, &v1.FeaturePort{
			Feature: v1.Feature_NODES,
			Port:    1,
		})
		if port := node.RPCPort(); port != 1 {
			t.Errorf("expected port for feature NODES to be 1, got %d", port)
		}
	})

	t.Run("NodeDNSPort", func(t *testing.T) {
		t.Parallel()
		node := MeshNode{&v1.MeshNode{}}
		// Features should always return 0 when not found.
		if port := node.DNSPort(); port != 0 {
			t.Errorf("expected port for feature DNS to be 0, got %d", port)
		}
		node.Features = append(node.Features, &v1.FeaturePort{
			Feature: v1.Feature_MESH_DNS,
			Port:    1,
		})
		if port := node.DNSPort(); port != 1 {
			t.Errorf("expected port for feature DNS to be 1, got %d", port)
		}
	})

	t.Run("NodeTURNPort", func(t *testing.T) {
		t.Parallel()
		node := MeshNode{&v1.MeshNode{}}
		// Features should always return 0 when not found.
		if port := node.TURNPort(); port != 0 {
			t.Errorf("expected port for feature TURN to be 0, got %d", port)
		}
		node.Features = append(node.Features, &v1.FeaturePort{
			Feature: v1.Feature_TURN_SERVER,
			Port:    1,
		})
		if port := node.TURNPort(); port != 1 {
			t.Errorf("expected port for feature TURN to be 1, got %d", port)
		}
	})

	t.Run("NodeStoragePort", func(t *testing.T) {
		t.Parallel()
		node := MeshNode{&v1.MeshNode{}}
		// Features should always return 0 when not found.
		if port := node.StoragePort(); port != 0 {
			t.Errorf("expected port for feature STORAGE_PROVIDER to be 0, got %d", port)
		}
		node.Features = append(node.Features, &v1.FeaturePort{
			Feature: v1.Feature_STORAGE_PROVIDER,
			Port:    1,
		})
		if port := node.StoragePort(); port != 1 {
			t.Errorf("expected port for feature STORAGE_PROVIDER to be 1, got %d", port)
		}
	})

	t.Run("NodePrivateAddrV4", func(t *testing.T) {
		t.Parallel()
		node := MeshNode{&v1.MeshNode{}}
		if addr := node.PrivateAddrV4(); addr.IsValid() {
			t.Errorf("expected private addr to be invalid, got %s", addr)
		}
		// Set to an invalid address and should still be invalid.
		node.PrivateIPv4 = "invalid"
		if addr := node.PrivateAddrV4(); addr.IsValid() {
			t.Errorf("expected private addr to be invalid, got %s", addr)
		}
		addr := netip.MustParsePrefix("172.16.0.1/32")
		node.PrivateIPv4 = addr.String()
		if got := node.PrivateAddrV4(); got != addr {
			t.Errorf("expected private addr to be %s, got %s", addr, got)
		}
	})

	t.Run("NodePrivateAddrV6", func(t *testing.T) {
		t.Parallel()
		node := MeshNode{&v1.MeshNode{}}
		if addr := node.PrivateAddrV6(); addr.IsValid() {
			t.Errorf("expected private addr to be invalid, got %s", addr)
		}
		// Set to an invalid address and should still be invalid.
		node.PrivateIPv6 = "invalid"
		if addr := node.PrivateAddrV6(); addr.IsValid() {
			t.Errorf("expected private addr to be invalid, got %s", addr)
		}
		addr := netip.MustParsePrefix("2001:db8::1/128")
		node.PrivateIPv6 = addr.String()
		if got := node.PrivateAddrV6(); got != addr {
			t.Errorf("expected private addr to be %s, got %s", addr, got)
		}
	})

	t.Run("NodePublicRPCAddr", func(t *testing.T) {
		t.Parallel()
		node := MeshNode{&v1.MeshNode{}}
		if addr := node.PublicRPCAddr(); addr.IsValid() {
			t.Errorf("expected public rpc addr to be invalid, got %s", addr)
		}
		// Set to a valid address but dont define an RPC port
		node.PrimaryEndpoint = "172.16.0.1"
		if addr := node.PublicRPCAddr(); addr.IsValid() {
			t.Errorf("expected public rpc addr to be invalid, got %s", addr)
		}
		// Define an RPC port
		node.Features = append(node.Features, &v1.FeaturePort{
			Feature: v1.Feature_NODES,
			Port:    1,
		})
		// Set to an invalid address and should still be invalid.
		node.PrimaryEndpoint = "invalid"
		if addr := node.PublicRPCAddr(); addr.IsValid() {
			t.Errorf("expected public rpc addr to be invalid, got %s", addr)
		}
		// Set to a valid address and should be valid.
		node.PrimaryEndpoint = "172.16.0.1"
		expected := netip.MustParseAddrPort("172.16.0.1:1")
		if got := node.PublicRPCAddr(); got != expected {
			t.Errorf("expected public rpc addr to be %s, got %s", expected, got)
		}
	})

	t.Run("NodePrivateRPCAddrV4", func(t *testing.T) {
		t.Parallel()
		node := MeshNode{&v1.MeshNode{}}
		if addr := node.PrivateRPCAddrV4(); addr.IsValid() {
			t.Errorf("expected private rpc addr to be invalid, got %s", addr)
		}
		// Set to a valid address but dont define an RPC port
		node.PrivateIPv4 = "172.16.0.1/32"
		if addr := node.PrivateRPCAddrV4(); addr.IsValid() {
			t.Errorf("expected private rpc addr to be invalid, got %s", addr)
		}
		// Define an RPC port
		node.Features = append(node.Features, &v1.FeaturePort{
			Feature: v1.Feature_NODES,
			Port:    1,
		})
		// Set to an invalid address and should still be invalid.
		node.PrivateIPv4 = "invalid"
		if addr := node.PrivateRPCAddrV4(); addr.IsValid() {
			t.Errorf("expected private rpc addr to be invalid, got %s", addr)
		}
		// Set to a valid address and should be valid.
		node.PrivateIPv4 = "172.16.0.1/32"
		expected := netip.MustParseAddrPort("172.16.0.1:1")
		if got := node.PrivateRPCAddrV4(); got != expected {
			t.Errorf("expected private rpc addr to be %s, got %s", expected, got)
		}
	})

	t.Run("NodePrivateRPCAddrV6", func(t *testing.T) {
		t.Parallel()
		node := MeshNode{&v1.MeshNode{}}
		if addr := node.PrivateRPCAddrV6(); addr.IsValid() {
			t.Errorf("expected private rpc addr to be invalid, got %s", addr)
		}
		// Set to a valid address but dont define an RPC port
		node.PrivateIPv6 = "2001:db8::1/128"
		if addr := node.PrivateRPCAddrV6(); addr.IsValid() {
			t.Errorf("expected private rpc addr to be invalid, got %s", addr)
		}
		// Define an RPC port
		node.Features = append(node.Features, &v1.FeaturePort{
			Feature: v1.Feature_NODES,
			Port:    1,
		})
		// Set to an invalid address and should still be invalid.
		node.PrivateIPv6 = "invalid"
		if addr := node.PrivateRPCAddrV6(); addr.IsValid() {
			t.Errorf("expected private rpc addr to be invalid, got %s", addr)
		}
		// Set to a valid address and should be valid.
		node.PrivateIPv6 = "2001:db8::1/128"
		expected := netip.MustParseAddrPort("[2001:db8::1]:1")
		if got := node.PrivateRPCAddrV6(); got != expected {
			t.Errorf("expected private rpc addr to be %s, got %s", expected, got)
		}
	})

	t.Run("NodePrivateStorageAddrV4", func(t *testing.T) {
		t.Parallel()
		node := MeshNode{&v1.MeshNode{}}
		if addr := node.PrivateStorageAddrV4(); addr.IsValid() {
			t.Errorf("expected private storage addr to be invalid, got %s", addr)
		}
		// Set to a valid address but dont define an RPC port
		node.PrivateIPv4 = "172.16.0.1/32"
		if addr := node.PrivateStorageAddrV4(); addr.IsValid() {
			t.Errorf("expected private storage addr to be invalid, got %s", addr)
		}
		// Define an RPC port
		node.Features = append(node.Features, &v1.FeaturePort{
			Feature: v1.Feature_STORAGE_PROVIDER,
			Port:    1,
		})
		// Set to an invalid address and should still be invalid.
		node.PrivateIPv4 = "invalid"
		if addr := node.PrivateStorageAddrV4(); addr.IsValid() {
			t.Errorf("expected private storage addr to be invalid, got %s", addr)
		}
		// Set to a valid address and should be valid.
		node.PrivateIPv4 = "172.16.0.1/32"
		expected := netip.MustParseAddrPort("172.16.0.1:1")
		if got := node.PrivateStorageAddrV4(); got != expected {
			t.Errorf("expected private storage addr to be %s, got %s", expected, got)
		}
	})

	t.Run("NodePrivateStorageAddrV6", func(t *testing.T) {
		t.Parallel()
		node := MeshNode{&v1.MeshNode{}}
		if addr := node.PrivateStorageAddrV6(); addr.IsValid() {
			t.Errorf("expected private storage addr to be invalid, got %s", addr)
		}
		// Set to a valid address but dont define an RPC port
		node.PrivateIPv6 = "2001:db8::1/128"
		if addr := node.PrivateStorageAddrV6(); addr.IsValid() {
			t.Errorf("expected private storage addr to be invalid, got %s", addr)
		}
		// Define an RPC port
		node.Features = append(node.Features, &v1.FeaturePort{
			Feature: v1.Feature_STORAGE_PROVIDER,
			Port:    1,
		})
		// Set to an invalid address and should still be invalid.
		node.PrivateIPv6 = "invalid"
		if addr := node.PrivateStorageAddrV6(); addr.IsValid() {
			t.Errorf("expected private storage addr to be invalid, got %s", addr)
		}
		// Set to a valid address and should be valid.
		node.PrivateIPv6 = "2001:db8::1/128"
		expected := netip.MustParseAddrPort("[2001:db8::1]:1")
		if got := node.PrivateStorageAddrV6(); got != expected {
			t.Errorf("expected private storage addr to be %s, got %s", expected, got)
		}
	})

	t.Run("NodePublicDNSAddr", func(t *testing.T) {
		t.Parallel()
		node := MeshNode{&v1.MeshNode{}}
		if addr := node.PublicDNSAddr(); addr.IsValid() {
			t.Errorf("expected public dns addr to be invalid, got %s", addr)
		}
		// Set to a valid address but dont define an RPC port
		node.PrimaryEndpoint = "172.16.0.1"
		if addr := node.PublicDNSAddr(); addr.IsValid() {
			t.Errorf("expected public dns addr to be invalid, got %s", addr)
		}
		// Define an RPC port
		node.Features = append(node.Features, &v1.FeaturePort{
			Feature: v1.Feature_MESH_DNS,
			Port:    1,
		})
		// Set to an invalid address and should still be invalid.
		node.PrimaryEndpoint = "invalid"
		if addr := node.PublicDNSAddr(); addr.IsValid() {
			t.Errorf("expected public dns addr to be invalid, got %s", addr)
		}
		// Set to a valid address and should be valid.
		node.PrimaryEndpoint = "172.16.0.1"
		expected := netip.MustParseAddrPort("172.16.0.1:1")
		if got := node.PublicDNSAddr(); got != expected {
			t.Errorf("expected public dns addr to be %s, got %s", expected, got)
		}
	})

	t.Run("NodePrivateDNSAddrV4", func(t *testing.T) {
		t.Parallel()
		node := MeshNode{&v1.MeshNode{}}
		if addr := node.PrivateDNSAddrV4(); addr.IsValid() {
			t.Errorf("expected private dns addr to be invalid, got %s", addr)
		}
		// Set to a valid address but dont define an RPC port
		node.PrivateIPv4 = "172.16.0.1/32"
		if addr := node.PrivateDNSAddrV4(); addr.IsValid() {
			t.Errorf("expected private dns addr to be invalid, got %s", addr)
		}
		// Define an RPC port
		node.Features = append(node.Features, &v1.FeaturePort{
			Feature: v1.Feature_MESH_DNS,
			Port:    1,
		})
		// Set to an invalid address and should still be invalid.
		node.PrivateIPv4 = "invalid"
		if addr := node.PrivateDNSAddrV4(); addr.IsValid() {
			t.Errorf("expected private dns addr to be invalid, got %s", addr)
		}
		// Set to a valid address and should be valid.
		node.PrivateIPv4 = "172.16.0.1/32"
		expected := netip.MustParseAddrPort("172.16.0.1:1")
		if got := node.PrivateDNSAddrV4(); got != expected {
			t.Errorf("expected private dns addr to be %s, got %s", expected, got)
		}
	})

	t.Run("NodePrivateDNSAddrV6", func(t *testing.T) {
		t.Parallel()
		node := MeshNode{&v1.MeshNode{}}
		if addr := node.PrivateDNSAddrV6(); addr.IsValid() {
			t.Errorf("expected private dns addr to be invalid, got %s", addr)
		}
		// Set to a valid address but dont define an RPC port
		node.PrivateIPv6 = "2001:db8::1/128"
		if addr := node.PrivateDNSAddrV6(); addr.IsValid() {
			t.Errorf("expected private dns addr to be invalid, got %s", addr)
		}
		// Define an RPC port
		node.Features = append(node.Features, &v1.FeaturePort{
			Feature: v1.Feature_MESH_DNS,
			Port:    1,
		})
		// Set to an invalid address and should still be invalid.
		node.PrivateIPv6 = "invalid"
		if addr := node.PrivateDNSAddrV6(); addr.IsValid() {
			t.Errorf("expected private dns addr to be invalid, got %s", addr)
		}
		// Set to a valid address and should be valid.
		node.PrivateIPv6 = "2001:db8::1/128"
		expected := netip.MustParseAddrPort("[2001:db8::1]:1")
		if got := node.PrivateDNSAddrV6(); got != expected {
			t.Errorf("expected private dns addr to be %s, got %s", expected, got)
		}
	})

	t.Run("NodePrivateTURNAddrV4", func(t *testing.T) {
		t.Parallel()
		node := MeshNode{&v1.MeshNode{}}
		if addr := node.PrivateTURNAddrV4(); addr.IsValid() {
			t.Errorf("expected private turn addr to be invalid, got %s", addr)
		}
		// Set to a valid address but dont define an RPC port
		node.PrivateIPv4 = "172.16.0.1/32"
		if addr := node.PrivateTURNAddrV4(); addr.IsValid() {
			t.Errorf("expected private turn addr to be invalid, got %s", addr)
		}
		// Define an RPC port
		node.Features = append(node.Features, &v1.FeaturePort{
			Feature: v1.Feature_TURN_SERVER,
			Port:    1,
		})
		// Set to an invalid address and should still be invalid.
		node.PrivateIPv4 = "invalid"
		if addr := node.PrivateTURNAddrV4(); addr.IsValid() {
			t.Errorf("expected private turn addr to be invalid, got %s", addr)
		}
		// Set to a valid address and should be valid.
		node.PrivateIPv4 = "172.16.0.1/32"
		expected := netip.MustParseAddrPort("172.16.0.1:1")
		if got := node.PrivateTURNAddrV4(); got != expected {
			t.Errorf("expected private turn addr to be %s, got %s", expected, got)
		}
	})

	t.Run("NodePrivateTURNAddrV6", func(t *testing.T) {
		t.Parallel()
		node := MeshNode{&v1.MeshNode{}}
		if addr := node.PrivateTURNAddrV6(); addr.IsValid() {
			t.Errorf("expected private turn addr to be invalid, got %s", addr)
		}
		// Set to a valid address but dont define an RPC port
		node.PrivateIPv6 = "2001:db8::1/128"
		if addr := node.PrivateTURNAddrV6(); addr.IsValid() {
			t.Errorf("expected private turn addr to be invalid, got %s", addr)
		}
		// Define an RPC port
		node.Features = append(node.Features, &v1.FeaturePort{
			Feature: v1.Feature_TURN_SERVER,
			Port:    1,
		})
		// Set to an invalid address and should still be invalid.
		node.PrivateIPv6 = "invalid"
		if addr := node.PrivateTURNAddrV6(); addr.IsValid() {
			t.Errorf("expected private turn addr to be invalid, got %s", addr)
		}
		// Set to a valid address and should be valid.
		node.PrivateIPv6 = "2001:db8::1/128"
		expected := netip.MustParseAddrPort("[2001:db8::1]:1")
		if got := node.PrivateTURNAddrV6(); got != expected {
			t.Errorf("expected private turn addr to be %s, got %s", expected, got)
		}
	})
}
