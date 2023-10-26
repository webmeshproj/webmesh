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

// Package config contains the wmctl CLI tool configuration.
package config

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/pflag"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"gopkg.in/yaml.v3"

	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/plugins/builtins/basicauth"
	"github.com/webmeshproj/webmesh/pkg/plugins/builtins/idauth"
	"github.com/webmeshproj/webmesh/pkg/plugins/builtins/ldap"
)

const (
	// APIVersion is the version of the API to use.
	APIVersion = "webmesh.io/v1"
	// Kind is the kind of the configuration. It should always be "Config".
	Kind = "Config"
	// DefaultServer is the default server to connect to.
	DefaultServer = "localhost:8443"
)

var (
	// DefaultConfigPath is the default path to the CLI configuration file.
	DefaultConfigPath = filepath.Join(".wmctl", "config.yaml")
)

func init() {
	userHomeDir, err := os.UserHomeDir()
	if err == nil {
		DefaultConfigPath = filepath.Join(userHomeDir, DefaultConfigPath)
	}
}

// New creates a new configuration.
func New() *Config {
	return &Config{
		APIVersion: APIVersion,
		Kind:       Kind,
	}
}

// FromFile creates a configuration from the given filename.
func FromFile(filename string) (*Config, error) {
	c := New()
	return c, c.LoadFile(filename)
}

// FromReader creates a configuration from the given reader.
func FromReader(r io.Reader) (*Config, error) {
	c := New()
	return c, c.Unmarshal(r)
}

// LoadFile loads the configuration from the given filename.
func (c *Config) LoadFile(filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	return c.Unmarshal(f)
}

// Unmarshal unmarshals the configuration from the given reader.
func (c *Config) Unmarshal(r io.Reader) error {
	return unmarshal(r, c)
}

// Marshal marshals the configuration to a writer.
func (c *Config) Marshal(w io.Writer) error {
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	return enc.Encode(c)
}

// WriteTo writes the configuration to a file.
func (c *Config) WriteTo(filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	return c.Marshal(f)
}

// Config is the wmctl CLI tool configuration.
type Config struct {
	// APIVersion is the version of the API to use.
	APIVersion string `yaml:"apiVersion" json:"apiVersion"`
	// Kind is the kind of the configuration. It should always be "Config".
	Kind string `yaml:"kind" json:"kind"`
	// Clusters is the list of clusters to connect to.
	Clusters []Cluster `yaml:"clusters,omitempty" json:"clusters,omitempty"`
	// Users is the list of users to connect as.
	Users []User `yaml:"users,omitempty" json:"users,omitempty"`
	// Contexts is the list of contexts to connect with.
	Contexts []Context `yaml:"contexts,omitempty" json:"contexts,omitempty"`
	// CurrentContext is the name of the current context.
	CurrentContext string `yaml:"current-context,omitempty" json:"current-context,omitempty"`
}

// Cluster is the named configuration for a cluster.
type Cluster struct {
	// Name is the name of the Cluster.
	Name string `yaml:"name" json:"name"`
	// Cluster is the configuration for the cluster.
	Cluster ClusterConfig `yaml:"cluster,omitempty" json:"cluster,omitempty"`
}

// ClusterConfig is the configuration for a cluster.
type ClusterConfig struct {
	// Server is the URL of a discovery node in the cluster.
	Server string `yaml:"server,omitempty" json:"server,omitempty"`
	// Insecure controls whether TLS should be disabled for the cluster connection.
	Insecure bool `yaml:"insecure,omitempty" json:"insecure,omitempty"`
	// TLSVerifyChainOnly controls whether only the cluster's TLS chain should be verified.
	TLSVerifyChainOnly bool `yaml:"tls-verify-chain-only,omitempty" json:"tls-verify-chain-only,omitempty"`
	// TLSSkipVerify controls whether the cluster's TLS certificate should be verified.
	TLSSkipVerify bool `yaml:"tls-skip-verify,omitempty" json:"tls-skip-verify,omitempty"`
	// CertificateAuthorityData is the base64-encoded certificate authority data for the cluster.
	CertificateAuthorityData string `yaml:"certificate-authority-data,omitempty" json:"certificate-authority-data,omitempty"`
	// PreferLeader controls whether the client should prefer to connect to the cluster leader.
	PreferLeader bool `yaml:"prefer-leader,omitempty" json:"prefer-leader,omitempty"`
	// ConnectTimeout is the timeout for connecting to the cluster.
	ConnectTimeout Duration `yaml:"connect-timeout,omitempty" json:"connect-timeout,omitempty"`
	// RequestTimeout is the timeout for requests to the cluster.
	RequestTimeout Duration `yaml:"request-timeout,omitempty" json:"request-timeout,omitempty"`
}

// User is the named configuration for a user.
type User struct {
	// Name is the name of the user.
	Name string `yaml:"name" json:"name"`
	// User is the configuration for the user.
	User UserConfig `yaml:"user,omitempty" json:"user,omitempty"`
}

// UserConfig is the configuration for a user.
type UserConfig struct {
	// ClientCertificateData is the base64-encoded client certificate data for the user.
	ClientCertificateData string `yaml:"client-certificate-data,omitempty" json:"client-certificate-data,omitempty"`
	// ClientKeyData is the base64-encoded client key data for the user.
	ClientKeyData string `yaml:"client-key-data,omitempty" json:"client-key-data,omitempty"`
	// BasicAuthUsername is the username for basic authentication.
	BasicAuthUsername string `yaml:"basic-auth-username,omitempty" json:"basic-auth-username,omitempty"`
	// BasicAuthPassword is the password for basic authentication.
	BasicAuthPassword string `yaml:"basic-auth-password,omitempty" json:"basic-auth-password,omitempty"`
	// LDAPUsername is the username for LDAP authentication.
	LDAPUsername string `yaml:"ldap-username,omitempty" json:"ldap-username,omitempty"`
	// LDAPPassword is the password for LDAP authentication.
	LDAPPassword string `yaml:"ldap-password,omitempty" json:"ldap-password,omitempty"`
	// IDAuthPrivateKey is the private key for ID authentication.
	IDAuthPrivateKey string `yaml:"id-auth-public-key,omitempty" json:"id-auth-public-key,omitempty"`
}

// Context is the named configuration for a context.
type Context struct {
	// Name is the name of the context.
	Name string `yaml:"name" json:"name"`
	// Context is the configuration for the context.
	Context ContextConfig `yaml:"context,omitempty" json:"context,omitempty"`
}

// ContextConfig is the configuration for a context.
type ContextConfig struct {
	// Cluster is the name of the cluster to connect to.
	Cluster string `yaml:"cluster,omitempty" json:"cluster,omitempty"`
	// User is the name of the user to connect as.
	User string `yaml:"user,omitempty" json:"user,omitempty"`
}

// NewNodeClient creates a new Node gRPC client for the current context.
func (c *Config) NewNodeClient() (v1.NodeClient, io.Closer, error) {
	conn, err := c.DialCurrent()
	if err != nil {
		return nil, nil, err
	}
	return v1.NewNodeClient(conn), conn, nil
}

// NewMeshClient creates a new Mesh gRPC client for the current context.
func (c *Config) NewMeshClient() (v1.MeshClient, io.Closer, error) {
	conn, err := c.DialCurrent()
	if err != nil {
		return nil, nil, err
	}
	return v1.NewMeshClient(conn), conn, nil
}

// NewWebRTCClient creates a new WebRTC gRPC client for the current context.
func (c *Config) NewWebRTCClient() (v1.WebRTCClient, io.Closer, error) {
	conn, err := c.DialCurrent()
	if err != nil {
		return nil, nil, err
	}
	return v1.NewWebRTCClient(conn), conn, nil
}

// NewAdminClient creates a new Admin gRPC client for the current context.
func (c *Config) NewAdminClient() (v1.AdminClient, io.Closer, error) {
	conn, err := c.DialCurrent()
	if err != nil {
		return nil, nil, err
	}
	return v1.NewAdminClient(conn), conn, nil
}

// DialCurrent connects to the current context.
func (c *Config) DialCurrent() (*grpc.ClientConn, error) {
	cluster := c.GetCurrentCluster()
	if cluster.Server == "" {
		cluster.Server = DefaultServer
	}
	opts, err := c.GetDialOptions()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	if cluster.ConnectTimeout.Duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cluster.ConnectTimeout.Duration)
		defer cancel()
	}
	return grpc.DialContext(ctx, cluster.Server, opts...)
}

// GetDialOptions gets the credentials for the current context.
func (c *Config) GetDialOptions() ([]grpc.DialOption, error) {
	var opts []grpc.DialOption
	cluster := c.GetCurrentCluster()
	user := c.GetCurrentUser()
	if cluster.Insecure {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		creds, err := c.TLSConfig()
		if err != nil {
			return nil, fmt.Errorf("build client TLS config: %w", err)
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(creds)))
	}
	if user.IDAuthPrivateKey != "" {
		key, err := crypto.DecodePrivateKey(user.IDAuthPrivateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decode ID authentication key: %w", err)
		}
		opts = append(opts, idauth.NewCreds(key))
	}
	if user.BasicAuthUsername != "" && user.BasicAuthPassword != "" {
		opts = append(opts, basicauth.NewCreds(user.BasicAuthUsername, user.BasicAuthPassword))
	}
	if user.LDAPUsername != "" && user.LDAPPassword != "" {
		opts = append(opts, ldap.NewCreds(user.LDAPUsername, user.LDAPPassword))
	}
	if cluster.PreferLeader {
		opts = append(opts, grpc.WithUnaryInterceptor(LeaderUnaryClientInterceptor()))
		opts = append(opts, grpc.WithStreamInterceptor(LeaderStreamClientInterceptor()))
	}
	if cluster.RequestTimeout.Duration > 0 {
		timeout := cluster.RequestTimeout.Duration
		opts = append(opts, grpc.WithUnaryInterceptor(RequestTimeoutUnaryClientInterceptor(timeout)))
		opts = append(opts, grpc.WithStreamInterceptor(RequestTimeoutStreamClientInterceptor(timeout)))
	}
	if len(opts) == 0 {
		// We shouldn't have gotten here
		return nil, fmt.Errorf("no credentials specified for cluster")
	}
	return opts, nil
}

// GetCluster gets a cluster by name.
func (c *Config) GetCluster(name string) *ClusterConfig {
	for _, cluster := range c.Clusters {
		if cluster.Name == name {
			return &cluster.Cluster
		}
	}
	return &ClusterConfig{}
}

// GetUser gets a user by name.
func (c *Config) GetUser(name string) *UserConfig {
	for _, user := range c.Users {
		if user.Name == name {
			return &user.User
		}
	}
	return &UserConfig{}
}

// GetContext gets a context by name.
func (c *Config) GetContext(name string) *ContextConfig {
	for _, context := range c.Contexts {
		if context.Name == name {
			return &context.Context
		}
	}
	return &ContextConfig{}
}

// GetCurrentCluster returns the current cluster.
func (c *Config) GetCurrentCluster() *ClusterConfig {
	ctx := c.GetCurrentContext()
	return c.GetCluster(ctx.Cluster)
}

// GetCurrentUser returns the current user.
func (c *Config) GetCurrentUser() *UserConfig {
	ctx := c.GetCurrentContext()
	return c.GetUser(ctx.User)
}

// GetCurrentContext returns the current context.
func (c *Config) GetCurrentContext() *ContextConfig {
	return c.GetContext(c.CurrentContext)
}

// SetCurrentContext sets the current context.
func (c *Config) SetCurrentContext(name string) {
	c.CurrentContext = name
}

// TLSConfig returns the TLS configuration for the current context.
func (c *Config) TLSConfig() (*tls.Config, error) {
	config := &tls.Config{}
	cluster := c.GetCurrentCluster()
	var certpool *x509.CertPool
	var err error
	certpool, err = x509.SystemCertPool()
	if err != nil {
		certpool = x509.NewCertPool()
	}
	var ca *x509.Certificate
	if cluster.CertificateAuthorityData != "" {
		pemdata, err := base64.StdEncoding.DecodeString(cluster.CertificateAuthorityData)
		if err != nil {
			return nil, fmt.Errorf("decode CA data: %w", err)
		}
		ca, err = crypto.DecodeTLSCertificate(bytes.NewReader(pemdata))
		if err != nil {
			return nil, fmt.Errorf("read CA data: %w", err)
		}
		certpool.AddCert(ca)
	}
	config.RootCAs = certpool
	config.InsecureSkipVerify = cluster.TLSSkipVerify
	if cluster.TLSVerifyChainOnly {
		if ca == nil {
			// This shouldn't happen
			return nil, fmt.Errorf("no CA certificate specified")
		}
		config.InsecureSkipVerify = true
		config.VerifyPeerCertificate = crypto.VerifyCertificateChainOnly([]*x509.Certificate{ca})
	}
	currentUser := c.GetCurrentUser()
	var certs []tls.Certificate
	if currentUser.ClientCertificateData != "" && currentUser.ClientKeyData != "" {
		cert, err := base64.StdEncoding.DecodeString(currentUser.ClientCertificateData)
		if err != nil {
			return nil, fmt.Errorf("failed to decode client certificate: %w", err)
		}
		key, err := base64.StdEncoding.DecodeString(currentUser.ClientKeyData)
		if err != nil {
			return nil, fmt.Errorf("failed to decode client key: %w", err)
		}
		certificate, err := tls.X509KeyPair(cert, key)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate and key: %w", err)
		}
		certs = append(certs, certificate)
	}
	config.Certificates = certs
	return config, nil
}

// BindFlags binds the configuration to the given flagset. It should
// be called before flags are parsed.
func (c *Config) BindFlags(flags *pflag.FlagSet) {
	currentContext := c.CurrentContext
	var usrIdx, clusterIdx int
	if currentContext == "" {
		c.Contexts = append(c.Contexts, Context{
			Name: "flags",
			Context: ContextConfig{
				Cluster: "flags",
				User:    "flags",
			},
		})
		c.Users = append(c.Users, User{
			Name: "flags",
			User: UserConfig{},
		})
		c.Clusters = append(c.Clusters, Cluster{
			Name:    "flags",
			Cluster: ClusterConfig{},
		})
		c.CurrentContext = "flags"
		usrIdx = len(c.Users) - 1
		clusterIdx = len(c.Clusters) - 1
	} else {
		for _, context := range c.Contexts {
			if context.Name == currentContext {
				for j, user := range c.Users {
					if user.Name == context.Context.User {
						usrIdx = j
						break
					}
				}
				for j, cluster := range c.Clusters {
					if cluster.Name == context.Context.Cluster {
						clusterIdx = j
						break
					}
				}
				break
			}
		}
	}
	bindFlags(c, flags, usrIdx, clusterIdx)
}

func bindFlags(c *Config, flset *pflag.FlagSet, usrIdx, clusterIdx int) {
	fs := flag.NewFlagSet("", flag.ExitOnError)

	fs.StringVar(&c.CurrentContext, "context", c.CurrentContext, "The name of the context to use")
	fs.StringVar(&c.Clusters[clusterIdx].Cluster.Server, "server", c.Clusters[clusterIdx].Cluster.Server, "The URL of the node to connect to")
	fs.BoolVar(&c.Clusters[clusterIdx].Cluster.TLSSkipVerify, "tls-skip-verify", c.Clusters[clusterIdx].Cluster.TLSSkipVerify, "Whether TLS verification should be skipped for the cluster connection")
	fs.BoolVar(&c.Clusters[clusterIdx].Cluster.Insecure, "insecure", c.Clusters[clusterIdx].Cluster.Insecure, "Whether TLS should be disabled for the cluster connection")
	fs.BoolVar(&c.Clusters[clusterIdx].Cluster.PreferLeader, "prefer-leader", c.Clusters[clusterIdx].Cluster.PreferLeader, "Whether to prefer the leader node for the cluster connection")

	fs.Func("certificate-authority", "The path to the CA certificate for the cluster connection", func(s string) error {
		data, err := os.ReadFile(s)
		if err != nil {
			return err
		}
		c.Clusters[clusterIdx].Cluster.CertificateAuthorityData = base64.StdEncoding.EncodeToString(data)
		return nil
	})
	fs.Func("client-certificate", "The path to the client certificate for the user", func(s string) error {
		data, err := os.ReadFile(s)
		if err != nil {
			return err
		}
		c.Users[usrIdx].User.ClientCertificateData = base64.StdEncoding.EncodeToString(data)
		return nil
	})
	fs.Func("client-key", "The path to the client key for the user", func(s string) error {
		data, err := os.ReadFile(s)
		if err != nil {
			return err
		}
		c.Users[usrIdx].User.ClientKeyData = base64.StdEncoding.EncodeToString(data)
		return nil
	})
	fs.Func("id-auth-key", "The path to the ID authentication key for the user", func(s string) error {
		data, err := os.ReadFile(s)
		if err != nil {
			return err
		}
		c.Users[usrIdx].User.IDAuthPrivateKey = string(data)
		return nil
	})
	fs.Func("basic-auth-username", "The username for basic authentication", func(s string) error {
		c.Users[usrIdx].User.BasicAuthUsername = s
		return nil
	})
	fs.Func("basic-auth-password", "The password for basic authentication", func(s string) error {
		c.Users[usrIdx].User.BasicAuthPassword = s
		return nil
	})
	fs.Func("ldap-username", "The username for LDAP authentication", func(s string) error {
		c.Users[usrIdx].User.LDAPUsername = s
		return nil
	})
	fs.Func("ldap-password", "The password for LDAP authentication", func(s string) error {
		c.Users[usrIdx].User.LDAPPassword = s
		return nil
	})

	flset.AddGoFlagSet(fs)
}

func unmarshal(r io.Reader, config interface{}) error {
	return yaml.NewDecoder(r).Decode(config)
}

type Duration struct{ time.Duration }

func (d Duration) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s"`, d.String())), nil
}

func (d *Duration) UnmarshalJSON(data []byte) error {
	duration, err := time.ParseDuration(string(data[1 : len(data)-1]))
	if err != nil {
		return err
	}
	*d = Duration{duration}
	return nil
}

func (d Duration) MarshalYAML() (interface{}, error) {
	return d.String(), nil
}

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("invalid duration: %s", value.Tag)
	}
	duration, err := time.ParseDuration(value.Value)
	if err != nil {
		return err
	}
	*d = Duration{duration}
	return nil
}
