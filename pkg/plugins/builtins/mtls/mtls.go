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

// Package mtls is an authentication plugin that uses mTLS.
package mtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/mitchellh/mapstructure"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/webmeshproj/webmesh/pkg/version"
)

// Plugin is the mTLS plugin.
type Plugin struct {
	v1.UnimplementedPluginServer
	v1.UnimplementedAuthPluginServer

	config *tls.Config
}

// Config is the configuration for the mTLS plugin.
type Config struct {
	// CAFile is the path to a CA file to use to verify client certificates.
	// If not provided, the system pool and any intermediate chains provided
	// in the authentication request will be used.
	CAFile string `mapstructure:"ca-file"`
}

func (p *Plugin) GetInfo(context.Context, *emptypb.Empty) (*v1.PluginInfo, error) {
	return &v1.PluginInfo{
		Name:        "mtls",
		Version:     version.Version,
		Description: "mTLS authentication plugin",
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
	if config.CAFile == "" {
		return nil, fmt.Errorf("ca-file is required")
	}
	p.config = &tls.Config{}
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	data, err := os.ReadFile(config.CAFile)
	if err != nil {
		return nil, err
	}
	ok := roots.AppendCertsFromPEM(data)
	if !ok {
		return nil, fmt.Errorf("failed to parse CA file %q", config.CAFile)
	}
	p.config.ClientCAs = roots
	return &emptypb.Empty{}, nil
}

func (p *Plugin) Close(ctx context.Context, req *emptypb.Empty) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (p *Plugin) Authenticate(ctx context.Context, req *v1.AuthenticationRequest) (*v1.AuthenticationResponse, error) {
	if len(req.Certificates) == 0 {
		return nil, fmt.Errorf("no certificates provided")
	}
	cert, err := x509.ParseCertificate(req.Certificates[0])
	if err != nil {
		return nil, err
	}
	opts := x509.VerifyOptions{
		Roots:         p.config.ClientCAs,
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if len(req.GetCertificates()) > 1 {
		for _, cert := range req.Certificates[1:] {
			intermediate, err := x509.ParseCertificate(cert)
			if err != nil {
				return nil, err
			}
			opts.Intermediates.AddCert(intermediate)
		}
	}
	_, err = cert.Verify(opts)
	if err != nil {
		return nil, err
	}
	commonName := cert.Subject.CommonName
	if commonName == "" {
		return nil, fmt.Errorf("no common name in certificate")
	}
	return &v1.AuthenticationResponse{
		Id: commonName,
	}, nil
}
