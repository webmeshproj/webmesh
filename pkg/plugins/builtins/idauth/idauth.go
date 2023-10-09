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

// Package idauth is an authentication plugin based on libp2p peer IDs.
// The public key is extracted from the ID and the authentication payload
// is a signature of the ID corresponding to the private key.
package idauth

import (
	"context"
	"fmt"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/pflag"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/version"
)

// Plugin is the ID auth plugin.
type Plugin struct {
	v1.UnimplementedPluginServer
	v1.UnimplementedAuthPluginServer
}

// Config is the configuration for the ID auth plugin.
// There are currently no configuration options.
type Config struct {
	// Enabled is a flag that can be used to disable the plugin.
	Enabled bool `mapstructure:"enabled" koanf:"enabled"`
}

func (c *Config) BindFlags(prefix string, fs *pflag.FlagSet) {
	fs.BoolVar(&c.Enabled, prefix+"enabled", c.Enabled, "enable the plugin")
}

func (c *Config) AsMapStructure() map[string]any {
	return map[string]any{
		"enabled": c.Enabled,
	}
}

func (c *Config) SetMapStructure(in map[string]any) {
	_ = mapstructure.Decode(in, c)
}

const (
	peerIDHeader    = "x-webmesh-id-auth-peer-id"
	signatureHeader = "x-webmesh-id-auth-signature"
)

func (p *Plugin) GetInfo(context.Context, *emptypb.Empty) (*v1.PluginInfo, error) {
	return &v1.PluginInfo{
		Name:        "id-auth",
		Version:     version.Version,
		Description: "ID authentication plugin",
		Capabilities: []v1.PluginInfo_PluginCapability{
			v1.PluginInfo_AUTH,
		},
	}, nil
}

func (p *Plugin) Configure(ctx context.Context, req *v1.PluginConfiguration) (*emptypb.Empty, error) {
	// Configure is a no-op. The flags above are only for exposing the plugin
	// to the CLI.
	return &emptypb.Empty{}, nil
}

func (p *Plugin) Authenticate(ctx context.Context, req *v1.AuthenticationRequest) (*v1.AuthenticationResponse, error) {
	// We should be able to extract a public key from the ID and verify that the ID
	// was signed by the private key for it.
	id, ok := req.GetHeaders()[peerIDHeader]
	if !ok {
		return nil, fmt.Errorf("missing %s header", peerIDHeader)
	}
	sig, ok := req.GetHeaders()[signatureHeader]
	if !ok {
		return nil, fmt.Errorf("missing %s header", signatureHeader)
	}
	pubKey, err := crypto.PubKeyFromID(peer.ID(id))
	if err != nil {
		return nil, fmt.Errorf("failed to extract public key from ID: %w", err)
	}
	valid, err := pubKey.Verify([]byte(id), []byte(sig))
	if err != nil {
		return nil, fmt.Errorf("failed to verify signature: %w", err)
	}
	if !valid {
		return nil, fmt.Errorf("invalid signature")
	}
	return &v1.AuthenticationResponse{
		Id: id,
	}, nil
}

func (p *Plugin) Close(ctx context.Context, req *emptypb.Empty) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
