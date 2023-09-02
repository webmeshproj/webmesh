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

// Package ipam provides a plugin for simple mesh IPAM. It also acts as a storage
// plugin and uses the leases tracked in the mesh database to pseudo-randomly
// assign IP addresses to nodes.
package ipam

import (
	"flag"
	"fmt"
	"net/netip"
	"strings"
	"sync"

	"github.com/mitchellh/mapstructure"
	"github.com/spf13/pflag"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/meshdb/peers"
	"github.com/webmeshproj/webmesh/pkg/plugins/plugindb"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/version"
)

// Plugin is the ipam plugin.
type Plugin struct {
	v1.UnimplementedPluginServer
	v1.UnimplementedIPAMPluginServer
	v1.UnimplementedStoragePluginServer

	config  Config
	data    storage.MeshStorage
	datamux sync.Mutex
	closec  chan struct{}
}

// Config contains static address assignments for nodes.
type Config struct {
	// StaticIPv4 is a map of node names to IPv4 addresses.
	StaticIPv4 map[string]any `mapstructure:"static-ipv4,omitempty" koanf:"static-ipv4,omitempty"`
}

type mapstructureFlag map[string]any

func (f mapstructureFlag) String() string {
	if f == nil {
		return ""
	}
	return fmt.Sprintf("%v", map[string]any(f))
}

func (f mapstructureFlag) Set(s string) error {
	if f == nil {
		f = make(map[string]any)
	}
	parts := strings.Split(s, ",")
	for _, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			return fmt.Errorf("invalid key-value pair: %s", part)
		}
		f[kv[0]] = kv[1]
	}
	return nil
}

// BindFlags binds the plugin flags to the given flag set.
func (c *Config) BindFlags(prefix string, fs *pflag.FlagSet) {
	fl := mapstructureFlag(c.StaticIPv4)
	fs.AddGoFlag(&flag.Flag{
		Name:     prefix + "static-ipv4",
		Usage:    "Static IPv4 addresses to assign to nodes",
		Value:    &fl,
		DefValue: "",
	})
}

func (c *Config) AsMapStructure() map[string]any {
	return map[string]any{
		"static-ipv4": c.StaticIPv4,
	}
}

// DefaultOptions returns the default options for the plugin.
func (c *Config) DefaultOptions() *Config {
	return &Config{}
}

func (p *Plugin) GetInfo(context.Context, *emptypb.Empty) (*v1.PluginInfo, error) {
	return &v1.PluginInfo{
		Name:        "ipam",
		Version:     version.Version,
		Description: "Simple IPAM plugin",
		Capabilities: []v1.PluginInfo_PluginCapability{
			v1.PluginInfo_IPAMV4,
			v1.PluginInfo_STORAGE,
		},
	}, nil
}

func (p *Plugin) Configure(ctx context.Context, req *v1.PluginConfiguration) (*emptypb.Empty, error) {
	p.closec = make(chan struct{})
	var config Config
	conf := req.Config.AsMap()
	if len(conf) > 0 {
		err := mapstructure.Decode(conf, &config)
		if err != nil {
			return nil, fmt.Errorf("decode config: %w", err)
		}
		context.LoggerFrom(ctx).Debug("loaded static assignments map", "config", config)
	}
	p.config = config
	return &emptypb.Empty{}, nil
}

func (p *Plugin) InjectQuerier(srv v1.StoragePlugin_InjectQuerierServer) error {
	p.datamux.Lock()
	p.data = plugindb.Open(srv)
	p.datamux.Unlock()
	select {
	case <-p.closec:
		return nil
	case <-srv.Context().Done():
		return srv.Context().Err()
	}
}

func (p *Plugin) Close(ctx context.Context, req *emptypb.Empty) (*emptypb.Empty, error) {
	p.datamux.Lock()
	defer p.datamux.Unlock()
	defer close(p.closec)
	if p.data == nil {
		// Safeguard to make sure we don't get called before the query stream
		// is opened.
		return nil, fmt.Errorf("plugin not configured")
	}
	return &emptypb.Empty{}, p.data.Close()
}

func (p *Plugin) Allocate(ctx context.Context, r *v1.AllocateIPRequest) (*v1.AllocatedIP, error) {
	p.datamux.Lock()
	defer p.datamux.Unlock()
	if p.data == nil {
		// Safeguard to make sure we don't get called before the query stream
		// is opened.
		return nil, fmt.Errorf("plugin not configured")
	}
	if addr, ok := p.config.StaticIPv4[r.GetNodeId()]; ok {
		return &v1.AllocatedIP{
			Ip: addr.(string),
		}, nil
	}
	return p.allocateV4(ctx, r)
}

func (p *Plugin) allocateV4(ctx context.Context, r *v1.AllocateIPRequest) (*v1.AllocatedIP, error) {
	globalPrefix, err := netip.ParsePrefix(r.GetSubnet())
	if err != nil {
		return nil, fmt.Errorf("parse subnet: %w", err)
	}
	nodes, err := peers.New(p.data).List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	allocated := make(map[netip.Prefix]struct{}, len(nodes))
	for _, node := range nodes {
		n := node
		if n.PrivateAddrV4().IsValid() {
			allocated[n.PrivateAddrV4()] = struct{}{}
		}
	}
	prefix, err := p.next32(globalPrefix, allocated)
	if err != nil {
		return nil, fmt.Errorf("find next available IPv4: %w", err)
	}
	return &v1.AllocatedIP{
		Ip: prefix.String(),
	}, nil
}

// TODO: Release is not implemented server-side yet either.
func (p *Plugin) Release(context.Context, *v1.ReleaseIPRequest) (*emptypb.Empty, error) {
	// No-op, we don't actually track leases explicitly
	return &emptypb.Empty{}, nil
}

func (p *Plugin) next32(cidr netip.Prefix, set map[netip.Prefix]struct{}) (netip.Prefix, error) {
	ip := cidr.Addr().Next()
	for cidr.Contains(ip) {
		prefix := netip.PrefixFrom(ip, 32)
		if _, ok := set[prefix]; !ok && !p.isStaticAllocation(prefix) {
			return prefix, nil
		}
		ip = ip.Next()
	}
	return netip.Prefix{}, fmt.Errorf("no more addresses in %s", cidr)
}

func (p *Plugin) isStaticAllocation(ip netip.Prefix) bool {
	if ip.Addr().Is4() {
		for _, addr := range p.config.StaticIPv4 {
			if addr == ip.String() {
				return true
			}
		}
		return false
	}
	return false
}
