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

// Package basicauth is an authentication plugin that uses basic auth.
package basicauth

import (
	"context"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/mitchellh/mapstructure"
	"github.com/spf13/pflag"
	v1 "github.com/webmeshproj/api/v1"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/webmeshproj/webmesh/pkg/version"
)

// Plugin is the basicauth plugin.
type Plugin struct {
	v1.UnimplementedPluginServer
	v1.UnimplementedAuthPluginServer

	users map[string]string
	mux   sync.RWMutex
}

// Config is the configuration for the basic auth plugin.
type Config struct {
	// HTPasswdFile is the path to an htpasswd file to use to verify client
	// credentials.
	HTPasswdFile string `mapstructure:"htpasswd-file" koanf:"htpasswd-file"`
}

func (c *Config) BindFlags(prefix string, fs *pflag.FlagSet) {
	fs.StringVar(&c.HTPasswdFile, prefix+"htpasswd-file", c.HTPasswdFile, "path to htpasswd file")
}

func (c *Config) AsMapStructure() map[string]any {
	return map[string]any{
		"htpasswd-file": c.HTPasswdFile,
	}
}

// DefaultOptions returns the default options for the plugin.
func (c *Config) DefaultOptions() *Config {
	return &Config{}
}

const (
	usernameHeader = "x-webmesh-basic-auth-username"
	passwordHeader = "x-webmesh-basic-auth-password"
)

func (p *Plugin) GetInfo(context.Context, *emptypb.Empty) (*v1.PluginInfo, error) {
	return &v1.PluginInfo{
		Name:        "basic-auth",
		Version:     version.Version,
		Description: "Basic authentication plugin",
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
	if config.HTPasswdFile == "" {
		return nil, fmt.Errorf("htpasswd-file is required")
	}
	f, err := os.Open(config.HTPasswdFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := csv.NewReader(f)
	r.Comma = ':'
	r.Comment = '#'
	r.TrimLeadingSpace = true
	records, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	p.users = make(map[string]string)
	for _, record := range records {
		p.users[record[0]] = record[1]
	}
	return &emptypb.Empty{}, nil
}

func (p *Plugin) Authenticate(ctx context.Context, req *v1.AuthenticationRequest) (*v1.AuthenticationResponse, error) {
	p.mux.RLock()
	defer p.mux.RUnlock()
	username, ok := req.GetHeaders()[usernameHeader]
	if !ok {
		return nil, fmt.Errorf("missing %s header", usernameHeader)
	}
	password, ok := req.GetHeaders()[passwordHeader]
	if !ok {
		return nil, fmt.Errorf("missing %s header", passwordHeader)
	}
	if !p.verify(username, password) {
		return nil, fmt.Errorf("invalid credentials")
	}
	return &v1.AuthenticationResponse{
		Id: username,
	}, nil
}

func (p *Plugin) Close(ctx context.Context, req *emptypb.Empty) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (p *Plugin) verify(username, password string) bool {
	if p.users == nil {
		return false
	}
	hashed, ok := p.users[username]
	if !ok {
		return false
	}
	if strings.HasPrefix(hashed, "{SHA}") {
		hashed = hashed[5:]
		d := sha1.New()
		d.Write([]byte(password))
		return subtle.ConstantTimeCompare([]byte(hashed), []byte(base64.StdEncoding.EncodeToString(d.Sum(nil)))) == 1
	}
	if strings.HasPrefix(hashed, "$2") {
		return bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password)) == nil
	}
	return false
}
