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
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

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

	allowedIDs []string
}

// Config is the configuration for the ID auth plugin.
type Config struct {
	// AllowedIDs is a list of allowed peer IDs.
	AllowedIDs []string `mapstructure:"allowed-ids,omitempty" koanf:"allowed-ids,omitempty"`
	// IDFile is the path to a file containing a list of allowed peer IDs.
	// This can be a local file or a file in a remote HTTP(S) location.
	IDFile string `mapstructure:"id-file,omitempty" koanf:"id-file,omitempty"`
}

func (c *Config) BindFlags(prefix string, fs *pflag.FlagSet) {
	fs.StringSliceVar(&c.AllowedIDs, prefix+"allowed-ids", nil, "List of allowed peer IDs")
	fs.StringVar(&c.IDFile, prefix+"id-file", "", "Path to a file containing a list of allowed peer IDs")
}

func (c *Config) AsMapStructure() map[string]any {
	return map[string]any{
		"allowed-ids": c.AllowedIDs,
		"id-file":     c.IDFile,
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
	var config Config
	err := mapstructure.Decode(req.Config.AsMap(), &config)
	if err != nil {
		return nil, err
	}
	p.allowedIDs = config.AllowedIDs
	if config.IDFile != "" {
		var idData []byte
		switch {
		case strings.HasPrefix(config.IDFile, "http://"), strings.HasPrefix(config.IDFile, "https://"):
			resp, err := http.Get(config.IDFile)
			if err != nil {
				return nil, fmt.Errorf("failed to fetch ID file: %w", err)
			}
			defer resp.Body.Close()
			idData, err = io.ReadAll(resp.Body)
			if err != nil {
				return nil, fmt.Errorf("failed to read ID file: %w", err)
			}
		default:
			fname := strings.TrimPrefix(config.IDFile, "file://")
			idData, err = os.ReadFile(fname)
			if err != nil {
				return nil, fmt.Errorf("failed to read ID file: %w", err)
			}
		}
		ids := strings.Split(string(idData), "\n")
		for _, id := range ids {
			if id == "" {
				continue
			}
			p.allowedIDs = append(p.allowedIDs, id)
		}
	}
	return &emptypb.Empty{}, nil
}

func (p *Plugin) Authenticate(ctx context.Context, req *v1.AuthenticationRequest) (*v1.AuthenticationResponse, error) {
	// We should be able to extract a public key from the ID and verify that the ID
	// was signed by the private key for it.
	id, ok := req.GetHeaders()[peerIDHeader]
	if !ok {
		return nil, fmt.Errorf("missing %s header", peerIDHeader)
	}
	// Fast path, make sure it's in the list of allowed IDs.
	if !p.isAllowedID(id) {
		return nil, fmt.Errorf("peer ID %s is not in the allow list", id)
	}
	encodedSig, ok := req.GetHeaders()[signatureHeader]
	if !ok {
		return nil, fmt.Errorf("missing %s header", signatureHeader)
	}
	sig, err := base64.StdEncoding.DecodeString(encodedSig)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}
	pubKey, err := crypto.PubKeyFromID(id)
	if err != nil {
		return nil, fmt.Errorf("failed to extract public key from ID: %w", err)
	}
	valid, err := pubKey.Verify([]byte(id), sig)
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

func (p *Plugin) isAllowedID(id string) bool {
	for _, allowedID := range p.allowedIDs {
		if allowedID == id {
			return true
		}
	}
	return false
}
