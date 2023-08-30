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

// Package ldap implements a basic LDAP authentication plugin.
package ldap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/pflag"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/webmeshproj/webmesh/pkg/version"
)

// ErrInvalidCredentials is returned when the credentials are invalid.
var ErrInvalidCredentials = fmt.Errorf("invalid credentials")

// ErrUserDisabled is returned when the user is disabled.
var ErrUserDisabled = fmt.Errorf("user disabled")

// Plugin is the ldap plugin.
type Plugin struct {
	v1.UnimplementedPluginServer
	v1.UnimplementedAuthPluginServer

	config Config
	mux    sync.RWMutex
}

// Config is the configuration for the LDAP plugin.
type Config struct {
	// Server is the LDAP server to connect to. Specify as ldap[s]://host[:port].
	Server string `mapstructure:"server" koanf:"server"`
	// BindDN is the DN to bind with.
	BindDN string `mapstructure:"bind-dn" koanf:"bind-dn"`
	// BindPassword is the password to bind with.
	BindPassword string `mapstructure:"bind-password" koanf:"bind-password"`
	// CAFile is the path to a CA file to use to verify the LDAP server's certificate.
	CAFile string `mapstructure:"ca-file" koanf:"ca-file"`
	// UserBaseDN is the base DN to use to search for users. If empty, the entire
	// directory will be searched.
	UserBaseDN string `mapstructure:"user-base-dn" koanf:"user-base-dn"`
	// UserIDAttribute is the attribute to use to identify the user.
	UserIDAttribute string `mapstructure:"user-id-attribute" koanf:"user-id-attribute"`
	// NodeIDAttribute is the attribute to use to identify the node. If not specified, the
	// UserIDAttribute will be used.
	NodeIDAttribute string `mapstructure:"node-id-attribute" koanf:"node-id-attribute"`
	// UserDisabledAttribute is the attribute to use to determine if the user is disabled.
	// If not specified, all user's will be considered active.
	UserDisabledAttribute string `mapstructure:"user-status-attribute" koanf:"user-status-attribute"`
	// UserDisabledValue is the value of the UserStatusAttribute that indicates the user is disabled.
	// If not specified, any non-empty value of the UserDisabledAttribute will be considered disabled.
	UserDisabledValue string `mapstructure:"user-disabled-value" koanf:"user-disabled-value"`
}

// BindFlags binds the flags to the config.
func (c *Config) BindFlags(prefix string, fs *pflag.FlagSet) {
	fs.StringVar(&c.Server, prefix+"server", c.Server, "LDAP server to connect to")
	fs.StringVar(&c.BindDN, prefix+"bind-dn", c.BindDN, "DN to bind with")
	fs.StringVar(&c.BindPassword, prefix+"bind-password", c.BindPassword, "Password to bind with")
	fs.StringVar(&c.CAFile, prefix+"ca-file", c.CAFile, "Path to CA file to use to verify the LDAP server's certificate")
	fs.StringVar(&c.UserBaseDN, prefix+"user-base-dn", c.UserBaseDN, "Base DN to use to search for users")
	fs.StringVar(&c.UserIDAttribute, prefix+"user-id-attribute", c.UserIDAttribute, "Attribute to use to identify the user")
	fs.StringVar(&c.NodeIDAttribute, prefix+"node-id-attribute", c.NodeIDAttribute, "Attribute to use to identify the node")
	fs.StringVar(&c.UserDisabledAttribute, prefix+"user-status-attribute", c.UserDisabledAttribute, "Attribute to use to determine if the user is disabled")
	fs.StringVar(&c.UserDisabledValue, prefix+"user-disabled-value", c.UserDisabledValue, "Value of the user status attribute that indicates the user is disabled")
}

func (c *Config) AsMapStructure() map[string]any {
	return map[string]any{
		"server":                c.Server,
		"bind-dn":               c.BindDN,
		"bind-password":         c.BindPassword,
		"ca-file":               c.CAFile,
		"user-base-dn":          c.UserBaseDN,
		"user-id-attribute":     c.UserIDAttribute,
		"node-id-attribute":     c.NodeIDAttribute,
		"user-status-attribute": c.UserDisabledAttribute,
		"user-disabled-value":   c.UserDisabledValue,
	}
}

// DefaultOptions returns the default options for the plugin.
func (c *Config) DefaultOptions() *Config {
	return &Config{}
}

const (
	usernameHeader = "x-webmesh-ldap-auth-username"
	passwordHeader = "x-webmesh-ldap-auth-password"
)

func (p *Plugin) GetInfo(context.Context, *emptypb.Empty) (*v1.PluginInfo, error) {
	return &v1.PluginInfo{
		Name:        "ldap",
		Version:     version.Version,
		Description: "LDAP authentication plugin",
		Capabilities: []v1.PluginInfo_PluginCapability{
			v1.PluginInfo_AUTH,
		},
	}, nil
}

func (p *Plugin) Configure(ctx context.Context, req *v1.PluginConfiguration) (*emptypb.Empty, error) {
	p.mux.Lock()
	defer p.mux.Unlock()
	var config Config
	err := mapstructure.Decode(req.Config.AsMap(), &config)
	if err != nil {
		return nil, err
	}
	if config.Server == "" {
		return nil, fmt.Errorf("server is required")
	}
	if config.BindDN == "" {
		return nil, fmt.Errorf("bind-dn is required")
	}
	if config.BindPassword == "" {
		return nil, fmt.Errorf("bind-password is required")
	}
	if config.UserIDAttribute == "" {
		return nil, fmt.Errorf("user-id-attribute is required")
	}
	if config.NodeIDAttribute == "" {
		config.NodeIDAttribute = config.UserIDAttribute
	}
	p.config = config
	return &emptypb.Empty{}, nil
}

func (p *Plugin) Authenticate(ctx context.Context, req *v1.AuthenticationRequest) (*v1.AuthenticationResponse, error) {
	username, ok := req.GetHeaders()[usernameHeader]
	if !ok {
		return nil, fmt.Errorf("missing %s header", usernameHeader)
	}
	password, ok := req.GetHeaders()[passwordHeader]
	if !ok {
		return nil, fmt.Errorf("missing %s header", passwordHeader)
	}
	conn, err := p.dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("dial LDAP server: %w", err)
	}
	defer conn.Close()
	if err := p.bind(ctx, conn); err != nil {
		return nil, fmt.Errorf("bind: %w", err)
	}
	// Loookup the user.
	baseDN := p.config.UserBaseDN
	if baseDN == "" {
		baseDN, err = p.getBaseDN()
		if err != nil {
			return nil, fmt.Errorf("get base DN: %w", err)
		}
	}
	var timeout time.Duration
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	} else {
		timeout = 10 * time.Second
	}
	attrs := []string{"cn", "dn", p.config.UserIDAttribute}
	if p.config.NodeIDAttribute != p.config.UserIDAttribute {
		attrs = append(attrs, p.config.NodeIDAttribute)
	}
	if p.config.UserDisabledAttribute != "" {
		attrs = append(attrs, p.config.UserDisabledAttribute)
	}
	resp, err := conn.Search(ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,                      // Limit
		int(timeout.Seconds()), // Timeout
		false,                  // Types only
		fmt.Sprintf("(%s=%s)", p.config.UserIDAttribute, username), // User filter
		attrs, // User attrs
		nil,
	))
	if err != nil {
		return nil, fmt.Errorf("search: %w", err)
	}
	if len(resp.Entries) == 0 {
		return nil, ErrInvalidCredentials
	}
	user := resp.Entries[0]
	// Check if the user is disabled.
	if p.config.UserDisabledAttribute != "" {
		var disabled bool
		disabledAttr := user.GetAttributeValue(p.config.UserDisabledAttribute)
		if p.config.UserDisabledValue != "" {
			disabled = disabledAttr == p.config.UserDisabledValue
		} else {
			disabled = disabledAttr != ""
		}
		if disabled {
			return nil, ErrUserDisabled
		}
	}
	// Bind as the user to verify the password.
	if err := conn.Bind(user.DN, password); err != nil {
		return nil, ErrInvalidCredentials
	}
	nodeID := user.GetAttributeValue(p.config.UserIDAttribute)
	if p.config.NodeIDAttribute != p.config.UserIDAttribute {
		nodeID = user.GetAttributeValue(p.config.NodeIDAttribute)
	}
	return &v1.AuthenticationResponse{
		Id: nodeID,
	}, nil
}

func (p *Plugin) Close(ctx context.Context, req *emptypb.Empty) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (p *Plugin) bind(ctx context.Context, conn *ldap.Conn) error {
	return conn.Bind(p.config.BindDN, p.config.BindPassword)
}

func (p *Plugin) getBaseDN() (string, error) {
	parts := strings.Split(p.config.BindDN, ",")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid bind DN: %s", p.config.BindDN)
	}
	var sb strings.Builder
	for i, part := range parts {
		if strings.HasPrefix(strings.ToLower(part), "dc=") {
			sb.WriteString(part)
			if i < len(parts)-1 {
				sb.WriteString(",")
			}
		}
	}
	return sb.String(), nil
}

func (p *Plugin) dial(ctx context.Context) (*ldap.Conn, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(10 * time.Second)
	}
	opts := []ldap.DialOpt{
		ldap.DialWithDialer(&net.Dialer{
			Deadline: deadline,
		}),
	}
	if strings.HasPrefix(p.config.Server, "ldaps://") {
		var config tls.Config
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if p.config.CAFile != "" {
			cert, err := os.ReadFile(p.config.CAFile)
			if err != nil {
				return nil, err
			}
			if ok := roots.AppendCertsFromPEM(cert); !ok {
				return nil, fmt.Errorf("failed to append certificate")
			}
		}
		config.RootCAs = roots
		opts = append(opts, ldap.DialWithTLSConfig(&config))
	}
	return ldap.DialURL(p.config.Server, opts...)
}
