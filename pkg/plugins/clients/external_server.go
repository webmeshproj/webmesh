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

package clients

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/webmeshproj/webmesh/pkg/context"
)

// ExternalServerConfig is the configuration for an external plugin server.
type ExternalServerConfig struct {
	// Server is the address of a server for the plugin.
	Server string `yaml:"server,omitempty" json:"server,omitempty" toml:"server,omitempty"`
	// Insecure is whether to use an insecure connection to the plugin server.
	Insecure bool `yaml:"insecure,omitempty" json:"insecure,omitempty" toml:"insecure,omitempty"`
	// TLSCAFile is the path to a CA for verifying certificates.
	TLSCAFile string `yaml:"tls-ca-file,omitempty" json:"tls-ca-file,omitempty" toml:"tls-ca-file,omitempty"`
	// TLSCertFile is the path to a certificate for authenticating to the plugin server.
	TLSCertFile string `yaml:"tls-cert-file,omitempty" json:"tls-cert-file,omitempty" toml:"tls-cert-file,omitempty"`
	// TLSKeyFile is the path to a key for authenticating to the plugin server.
	TLSKeyFile string `yaml:"tls-key-file,omitempty" json:"tls-key-file,omitempty" toml:"tls-key-file,omitempty"`
	// TLSSkipVerify is whether to skip verifying the plugin server's certificate.
	TLSSkipVerify bool `yaml:"tls-skip-verify,omitempty" json:"tls-skip-verify,omitempty" toml:"tls-skip-verify,omitempty"`
}

// NewExternalServerClient creates a new plugin client for an external plugin server.
func NewExternalServerClient(ctx context.Context, cfg *ExternalServerConfig) (PluginClient, error) {
	var opt grpc.DialOption
	if cfg.Insecure {
		opt = grpc.WithTransportCredentials(insecure.NewCredentials())
	} else {
		var tlsConfig tls.Config
		certPool, err := x509.SystemCertPool()
		if err != nil {
			certPool = x509.NewCertPool()
		}
		if cfg.TLSCAFile != "" {
			caCert, err := os.ReadFile(cfg.TLSCAFile)
			if err != nil {
				return nil, fmt.Errorf("read CA file: %w", err)
			}
			if ok := certPool.AppendCertsFromPEM(caCert); !ok {
				return nil, fmt.Errorf("append CA cert: %w", err)
			}
		}
		tlsConfig.RootCAs = certPool
		if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
			cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
			if err != nil {
				return nil, fmt.Errorf("load cert: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}
		if cfg.TLSSkipVerify {
			tlsConfig.InsecureSkipVerify = true
		}
		opt = grpc.WithTransportCredentials(credentials.NewTLS(&tlsConfig))
	}
	c, err := grpc.DialContext(ctx, cfg.Server, opt)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	return &externalServerPlugin{v1.NewPluginClient(c), c}, nil
}

type externalServerPlugin struct {
	v1.PluginClient
	conn *grpc.ClientConn
}

func (p *externalServerPlugin) Close(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	_, err := p.PluginClient.Close(ctx, in, opts...)
	if err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, p.conn.Close()
}

func (p *externalServerPlugin) Storage() v1.StoragePluginClient {
	return v1.NewStoragePluginClient(p.conn)
}

func (p *externalServerPlugin) Auth() v1.AuthPluginClient {
	return v1.NewAuthPluginClient(p.conn)
}

func (p *externalServerPlugin) Events() v1.WatchPluginClient {
	return v1.NewWatchPluginClient(p.conn)
}

func (p *externalServerPlugin) IPAM() v1.IPAMPluginClient {
	return v1.NewIPAMPluginClient(p.conn)
}
