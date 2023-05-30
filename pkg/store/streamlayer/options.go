/*
Copyright 2023.

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

package streamlayer

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"

	"golang.org/x/exp/slog"

	"github.com/webmeshproj/node/pkg/util"
)

const (
	ListenAddressEnvVar   = "STORE_STREAM_LAYER_LISTEN_ADDRESS"
	CertFileEnvVar        = "STORE_STREAM_LAYER_TLS_CERT_FILE"
	KeyFileEnvVar         = "STORE_STREAM_LAYER_TLS_KEY_FILE"
	CAFileEnvVar          = "STORE_STREAM_LAYER_TLS_CA_FILE"
	ClientCAFileEnvVar    = "STORE_STREAM_LAYER_TLS_CLIENT_CA_FILE"
	MTLSEnvVar            = "STORE_STREAM_LAYER_MTLS"
	VerifyChainOnlyEnvVar = "STORE_STREAM_LAYER_VERIFY_CHAIN_ONLY"
	InsecureEnvVar        = "STORE_STREAM_LAYER_INSECURE"
)

// Options are the StreamLayer options.
type Options struct {
	// ListenAddress is the address to listen on.
	ListenAddress string `yaml:"listen-address,omitempty" json:"listen-address,omitempty" toml:"listen-address,omitempty"`
	// TLSCertFile is the path to the TLS certificate file.
	TLSCertFile string `yaml:"tls-cert-file,omitempty" json:"tls-cert-file,omitempty" toml:"tls-cert-file,omitempty"`
	// TLSKeyFile is the path to the TLS key file.
	TLSKeyFile string `yaml:"tls-key-file,omitempty" json:"tls-key-file,omitempty" toml:"tls-key-file,omitempty"`
	// TLSCAFile is the path to the TLS CA file. If empty,
	// the system CA pool is used.
	TLSCAFile string `yaml:"tls-ca-file,omitempty" json:"tls-ca-file,omitempty" toml:"tls-ca-file,omitempty"`
	// TLSClientCAFile is the path to the TLS client CA file.
	// If empty, either TLSCAFile or the system CA pool is used.
	TLSClientCAFile string `yaml:"tls-client-ca-file,omitempty" json:"tls-client-ca-file,omitempty" toml:"tls-client-ca-file,omitempty"`
	// MTLS is true if mutual TLS is enabled.
	MTLS bool `yaml:"mtls,omitempty" json:"mtls,omitempty" toml:"mtls,omitempty"`
	// VerifyChainOnly is true if only the certificate chain should be verified.
	VerifyChainOnly bool `yaml:"verify-chain-only,omitempty" json:"verify-chain-only,omitempty" toml:"verify-chain-only,omitempty"`
	// Insecure is true if the transport is insecure.
	Insecure bool `yaml:"insecure,omitempty" json:"insecure,omitempty" toml:"insecure,omitempty"`
}

// NewOptions returns new StreamLayerOptions with sensible defaults.
func NewOptions() *Options {
	return &Options{
		ListenAddress: ":9443",
	}
}

// BindFlags binds the StreamLayer options to the given flag set.
func (o *Options) BindFlags(fs *flag.FlagSet) {
	fs.StringVar(&o.ListenAddress, "store.stream-layer.listen-address", util.GetEnvDefault(ListenAddressEnvVar, ":9443"),
		"Stream layer listen address.")
	fs.StringVar(&o.TLSCertFile, "store.stream-layer.tls-cert-file", util.GetEnvDefault(CertFileEnvVar, ""),
		"Stream layer TLS certificate file.")
	fs.StringVar(&o.TLSKeyFile, "store.stream-layer.tls-key-file", util.GetEnvDefault(KeyFileEnvVar, ""),
		"Stream layer TLS key file.")
	fs.StringVar(&o.TLSCAFile, "store.stream-layer.tls-ca-file", util.GetEnvDefault(CAFileEnvVar, ""),
		"Stream layer TLS CA file.")
	fs.StringVar(&o.TLSClientCAFile, "store.stream-layer.tls-client-ca-file", util.GetEnvDefault(ClientCAFileEnvVar, ""),
		"Stream layer TLS client CA file.")
	fs.BoolVar(&o.MTLS, "store.stream-layer.mtls", util.GetEnvDefault(MTLSEnvVar, "false") == "true",
		"Enable mutual TLS for the stream layer.")
	fs.BoolVar(&o.VerifyChainOnly, "store.stream-layer.verify-chain-only", util.GetEnvDefault(VerifyChainOnlyEnvVar, "false") == "true",
		"Only verify the certificate chain for the stream layer.")
	fs.BoolVar(&o.Insecure, "store.stream-layer.insecure", util.GetEnvDefault(InsecureEnvVar, "false") == "true",
		"Don't use TLS for the stream layer.")
}

// Validate validates the StreamLayer options.
func (o *Options) Validate() error {
	if o.ListenAddress == "" {
		return fmt.Errorf("listen address is required")
	}
	if o.Insecure {
		return nil
	}
	if o.TLSCertFile == "" {
		return fmt.Errorf("tls cert file is required")
	}
	if o.TLSKeyFile == "" {
		return fmt.Errorf("tls key file is required")
	}
	return nil
}

// ListenPort returns the port the options are configured to listen on.
func (o *Options) ListenPort() (int, error) {
	_, port, err := net.SplitHostPort(o.ListenAddress)
	if err != nil {
		return 0, err
	}
	portNum, err := strconv.Atoi(port)
	if err != nil {
		return 0, err
	}
	return portNum, nil
}

// TLSConfig returns the TLS configuration.
func (o *Options) TLSConfig() (*tls.Config, error) {
	if o.Insecure {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(o.TLSCertFile, o.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load x509 key pair: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		slog.Default().Warn("failed to load system cert pool", slog.String("error", err.Error()))
		pool = x509.NewCertPool()
	}
	if o.TLSCAFile != "" {
		ca, err := os.ReadFile(o.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("read ca file: %w", err)
		}
		if ok := pool.AppendCertsFromPEM(ca); !ok {
			return nil, fmt.Errorf("append certs from pem")
		}
	}
	clientPool := pool.Clone()
	if o.TLSClientCAFile != "" {
		ca, err := os.ReadFile(o.TLSClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("read client ca file: %w", err)
		}
		if ok := clientPool.AppendCertsFromPEM(ca); !ok {
			return nil, fmt.Errorf("append certs from pem")
		}
	}
	var clientAuth tls.ClientAuthType
	if o.MTLS {
		clientAuth = tls.RequireAndVerifyClientCert
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ClientCAs:    clientPool,
		ClientAuth:   clientAuth,
	}
	if o.VerifyChainOnly {
		config.InsecureSkipVerify = true
		config.VerifyPeerCertificate = util.VerifyChainOnly
	}
	return config, nil
}
