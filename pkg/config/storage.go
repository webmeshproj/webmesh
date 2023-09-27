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

package config

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/spf13/pflag"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/meshnet/transport"
	"github.com/webmeshproj/webmesh/pkg/meshnode"
	"github.com/webmeshproj/webmesh/pkg/storage"
	extstorage "github.com/webmeshproj/webmesh/pkg/storage/providers/external"
	passthroughstorage "github.com/webmeshproj/webmesh/pkg/storage/providers/passthrough"
	raftstorage "github.com/webmeshproj/webmesh/pkg/storage/providers/raftstorage"
)

// StorageProvider is a type of storage provider.
type StorageProvider string

const (
	// StorageProviderRaft is the builtin raft storage provider.
	StorageProviderRaft StorageProvider = "raft"
	// StorageProviderPassThrough is the passthrough storage provider.
	StorageProviderPassThrough StorageProvider = "passthrough"
	// StorageProviderExternal is an external storage provider.
	StorageProviderExternal StorageProvider = "external"
)

// IsValid checks if the storage provider is valid.
func (s StorageProvider) IsValid() bool {
	switch s {
	case StorageProviderRaft, StorageProviderPassThrough, StorageProviderExternal:
		return true
	case "": // Defaults to raft
		return true
	}
	return false
}

// StorageOptions are the storage options.
type StorageOptions struct {
	// InMemory is a flag to use in-memory storage.
	InMemory bool `koanf:"in-memory,omitempty"`
	// Path is the path to the storage directory.
	Path string `koanf:"path,omitempty"`
	// Provider is the storage provider. If empty, the default is used.
	Provider string `koanf:"provider,omitempty"`
	// Raft are the raft storage options.
	Raft RaftOptions `koanf:"raft,omitempty"`
	// External are the external storage options.
	External ExternalStorageOptions `koanf:"external,omitempty"`
	// LogLevel is the log level for the storage provider.
	LogLevel string `koanf:"log-level,omitempty"`
}

// NewStorageOptions creates a new storage options.
func NewStorageOptions() StorageOptions {
	return StorageOptions{
		Path:     raftstorage.DefaultDataDir,
		Provider: string(StorageProviderRaft),
		Raft:     NewRaftOptions(),
		External: NewExternalStorageOptions(),
		LogLevel: "info",
	}
}

// BindFlags binds the storage options to the flag set.
func (o *StorageOptions) BindFlags(prefix string, fs *pflag.FlagSet) {
	prefix = prefix + "storage."
	fs.BoolVar(&o.InMemory, prefix+"in-memory", false, "Use in-memory storage")
	fs.StringVar(&o.Path, prefix+"path", raftstorage.DefaultDataDir, "Path to the storage directory")
	fs.StringVar(&o.Provider, prefix+"provider", string(StorageProviderRaft), "Storage provider (defaults to raftstorage or passthrough depending on other options)")
	fs.StringVar(&o.LogLevel, prefix+"log-level", "info", "Log level for the storage provider")
	o.Raft.BindFlags(prefix+"raft.", fs)
	o.External.BindFlags(prefix+"external.", fs)
}

// Validate validates the storage options.
func (o *StorageOptions) Validate(isMember bool) error {
	provider := StorageProvider(o.Provider)
	if !provider.IsValid() {
		return fmt.Errorf("invalid storage provider: %s", o.Provider)
	}
	if provider == StorageProviderRaft {
		if isMember {
			if err := o.Raft.Validate(o.Path, o.InMemory); err != nil {
				return err
			}
		}
	}
	if provider == StorageProviderExternal {
		if err := o.External.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// ListenPort returns the port to listen on for the storage provider.
func (o *StorageOptions) ListenPort() int {
	if o.Provider == string(StorageProviderRaft) || o.Provider == "" {
		return o.Raft.ListenPort()
	}
	// TODO: Get the port from the external storage provider.
	return 0
}

// NewStorageProvider creates a new storage provider from the given options. If not a storage providing member, a node dialer
// is required for the passthrough storage provider.
func (o *Config) NewStorageProvider(ctx context.Context, node meshnode.Node, force bool) (storage.Provider, error) {
	if !o.IsStorageMember() {
		return passthroughstorage.NewProvider(o.Storage.NewPassthroughOptions(ctx, node)), nil
	}
	switch StorageProvider(o.Storage.Provider) {
	case StorageProviderRaft, "":
		return o.Storage.NewRaftStorageProvider(ctx, node, force)
	case StorageProviderExternal:
		return o.Storage.NewExternalStorageProvider(ctx, node.ID())
	case StorageProviderPassThrough:
		return passthroughstorage.NewProvider(o.Storage.NewPassthroughOptions(ctx, node)), nil
	default:
		return nil, fmt.Errorf("invalid storage provider: %s", o.Storage.Provider)
	}
}

// NewRaftStorageProvider returns a new raftstorage provider for the current configuration.
func (o *StorageOptions) NewRaftStorageProvider(ctx context.Context, node meshnode.Node, force bool) (storage.Provider, error) {
	transport, err := o.Raft.NewTransport(node)
	if err != nil {
		return nil, err
	}
	opts, err := o.NewRaftOptions(ctx, node, transport, force)
	if err != nil {
		return nil, err
	}
	return raftstorage.NewProvider(opts), nil
}

// NewExternalStorageProvider returns a new external storage provider for the current configuration.
func (o *StorageOptions) NewExternalStorageProvider(ctx context.Context, nodeID string) (storage.Provider, error) {
	opts, err := o.NewExternalStorageOptions(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	return extstorage.NewProvider(opts), nil
}

// NewRaftOptions returns a new raft options for the current configuration.
func (o *StorageOptions) NewRaftOptions(ctx context.Context, node meshnode.Node, transport transport.RaftTransport, force bool) (raftstorage.Options, error) {
	opts := raftstorage.NewOptions(node.ID(), transport)
	raftTransport, err := o.Raft.NewTransport(node)
	if err != nil {
		return opts, fmt.Errorf("create raft transport: %w", err)
	}
	opts.Transport = raftTransport
	opts.ClearDataDir = force
	opts.DataDir = o.Path
	opts.InMemory = o.InMemory
	opts.ConnectionPoolCount = o.Raft.ConnectionPoolCount
	opts.ConnectionTimeout = o.Raft.ConnectionTimeout
	opts.HeartbeatTimeout = o.Raft.HeartbeatTimeout
	opts.ElectionTimeout = o.Raft.ElectionTimeout
	opts.ApplyTimeout = o.Raft.ApplyTimeout
	opts.CommitTimeout = o.Raft.CommitTimeout
	opts.MaxAppendEntries = o.Raft.MaxAppendEntries
	opts.LeaderLeaseTimeout = o.Raft.LeaderLeaseTimeout
	opts.SnapshotInterval = o.Raft.SnapshotInterval
	opts.SnapshotThreshold = o.Raft.SnapshotThreshold
	opts.SnapshotRetention = o.Raft.SnapshotRetention
	opts.ObserverChanBuffer = o.Raft.ObserverChanBuffer
	opts.LogLevel = o.LogLevel
	return opts, nil
}

// NewPassthroughOptions returns a new passthrough options for the current configuration.
func (o *StorageOptions) NewPassthroughOptions(ctx context.Context, node meshnode.Node) passthroughstorage.Options {
	return passthroughstorage.Options{
		Dialer:   node,
		LogLevel: o.LogLevel,
	}
}

// NewExternalStorageOptions creates a new external storage options.
func (o *StorageOptions) NewExternalStorageOptions(ctx context.Context, nodeID string) (extstorage.Options, error) {
	opts := extstorage.Options{
		NodeID:   nodeID,
		Server:   o.External.Server,
		LogLevel: o.LogLevel,
	}
	if len(o.External.Config) > 0 {
		config, err := structpb.NewStruct(o.External.Config)
		if err != nil {
			return opts, err
		}
		opts.Config = &v1.PluginConfiguration{
			Config: config,
		}
	}
	if o.External.Insecure {
		context.LoggerFrom(ctx).Warn("Using insecure connection to external storage provider")
		return opts, nil
	}
	var err error
	opts.TLSConfig, err = o.External.NewTLSConfig(ctx)
	if err != nil {
		return opts, err
	}
	return opts, nil
}

// ExternalStorageOptions are the external storage options.
type ExternalStorageOptions struct {
	// Server is the address of a server for the plugin.
	Server string `koanf:"server,omitempty"`
	// Config is the configuration to pass to the plugin.
	Config PluginMapConfig `koanf:"config,omitempty"`
	// Insecure is whether to use an insecure connection to the plugin server.
	Insecure bool `koanf:"insecure,omitempty"`
	// TLSCAData is the base64 PEM-encoded CA data for verifying certificates.
	TLSCAData string `koanf:"tls-ca-data,omitempty"`
	// TLSCAFile is the path to a CA for verifying certificates.
	TLSCAFile string `koanf:"tls-ca-file,omitempty"`
	// TLSCertData is the base64 PEM-encoded certificate data for authenticating to the plugin server.
	TLSCertData string `koanf:"tls-cert-data,omitempty"`
	// TLSCertFile is the path to a certificate for authenticating to the plugin server.
	TLSCertFile string `koanf:"tls-cert-file,omitempty"`
	// TLSKeyData is the base64 PEM-encoded key data for authenticating to the plugin server.
	TLSKeyData string `koanf:"tls-key-data,omitempty"`
	// TLSKeyFile is the path to a key for authenticating to the plugin server.
	TLSKeyFile string `koanf:"tls-key-file,omitempty"`
	// TLSSkipVerify is whether to skip verifying the plugin server's certificate.
	TLSSkipVerify bool `koanf:"tls-skip-verify,omitempty"`
}

// NewExternalStorageOptions creates a new external storage options.
func NewExternalStorageOptions() ExternalStorageOptions {
	return ExternalStorageOptions{
		Config: make(PluginMapConfig),
	}
}

// BindFlags binds the external storage options to the flag set.
func (o *ExternalStorageOptions) BindFlags(prefix string, fs *pflag.FlagSet) {
	fs.StringVar(&o.Server, prefix+"server", o.Server, "Address of a server for the plugin")
	fs.Var(&o.Config, prefix+"config", "Configuration to pass to the plugin as key value pairs")
	fs.BoolVar(&o.Insecure, prefix+"insecure", o.Insecure, "Use an insecure connection to the plugin server")
	fs.StringVar(&o.TLSCAFile, prefix+"tls-ca-file", o.TLSCAFile, "Path to a CA for verifying certificates")
	fs.StringVar(&o.TLSCertFile, prefix+"tls-cert-file", o.TLSCertFile, "Path to a certificate for authenticating to the plugin server")
	fs.StringVar(&o.TLSKeyFile, prefix+"tls-key-file", o.TLSKeyFile, "Path to a key for authenticating to the plugin server")
	fs.BoolVar(&o.TLSSkipVerify, prefix+"tls-skip-verify", o.TLSSkipVerify, "Skip verifying the plugin server's certificate")
}

// Validate validates the external storage options.
func (o *ExternalStorageOptions) Validate() error {
	if o.Server == "" {
		return fmt.Errorf("external storage server is required")
	}
	return nil
}

// NewTLSConfig creates a new TLS config from the options.
func (o *ExternalStorageOptions) NewTLSConfig(ctx context.Context) (*tls.Config, error) {
	var conf tls.Config
	var roots *x509.CertPool
	var err error
	roots, err = x509.SystemCertPool()
	if err != nil {
		context.LoggerFrom(ctx).Warn("Failed to load system certificate pool, starting with empty pool")
		roots = x509.NewCertPool()
	}
	if o.TLSCAData != "" {
		data, err := base64.StdEncoding.DecodeString(o.TLSCAData)
		if err != nil {
			return nil, fmt.Errorf("failed to decode tls-ca-data: %w", err)
		}
		if !roots.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("failed to append tls-ca-data to certificate pool")
		}
	}
	if o.TLSCAFile != "" {
		data, err := os.ReadFile(o.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load tls-ca-file: %w", err)
		}
		if !roots.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("failed to append tls-ca-file to certificate pool")
		}
	}
	conf.RootCAs = roots
	if o.TLSCertFile != "" && o.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(o.TLSCertFile, o.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load tls-cert-file and tls-key-file: %w", err)
		}
		conf.Certificates = append(conf.Certificates, cert)
	}
	if o.TLSCertData != "" && o.TLSKeyData != "" {
		certData, err := base64.StdEncoding.DecodeString(o.TLSCertData)
		if err != nil {
			return nil, fmt.Errorf("failed to decode tls-cert-data: %w", err)
		}
		keyData, err := base64.StdEncoding.DecodeString(o.TLSKeyData)
		if err != nil {
			return nil, fmt.Errorf("failed to decode tls-key-data: %w", err)
		}
		cert, err := tls.X509KeyPair(certData, keyData)
		if err != nil {
			return nil, fmt.Errorf("failed to load tls-cert-data and tls-key-data: %w", err)
		}
		conf.Certificates = append(conf.Certificates, cert)
	}
	if o.TLSSkipVerify {
		context.LoggerFrom(ctx).Warn("Skipping verification of external storage server certificate")
		conf.InsecureSkipVerify = true
	}
	return &conf, nil
}
