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
	"bytes"
	"database/sql"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"

	_ "github.com/mattn/go-sqlite3"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/webmeshproj/node/pkg/context"
	"github.com/webmeshproj/node/pkg/meshdb/models"
	"github.com/webmeshproj/node/pkg/meshdb/raftlogs"
	"github.com/webmeshproj/node/pkg/meshdb/snapshots"
	"github.com/webmeshproj/node/pkg/util"
	"github.com/webmeshproj/node/pkg/version"
)

// Plugin is the ipam plugin.
type Plugin struct {
	v1.UnimplementedPluginServer
	v1.UnimplementedStoragePluginServer
	v1.UnimplementedIPAMPluginServer

	data                          *sql.DB
	currentTerm, lastAppliedIndex atomic.Uint64
	datamux                       sync.Mutex
}

func (p *Plugin) GetInfo(context.Context, *emptypb.Empty) (*v1.PluginInfo, error) {
	return &v1.PluginInfo{
		Name:        "ipam",
		Version:     version.Version,
		Description: "Simple IPAM plugin",
		Capabilities: []v1.PluginCapability{
			v1.PluginCapability_PLUGIN_CAPABILITY_STORE,
			v1.PluginCapability_PLUGIN_CAPABILITY_IPAMV4,
			v1.PluginCapability_PLUGIN_CAPABILITY_IPAMV6,
		},
	}, nil
}

func (p *Plugin) Configure(ctx context.Context, req *v1.PluginConfiguration) (*emptypb.Empty, error) {
	p.datamux.Lock()
	defer p.datamux.Unlock()
	var err error
	dataPath := "file:simple-ipam?mode=memory&cache=shared&_foreign_keys=on&_case_sensitive_like=on&synchronous=full"
	p.data, err = sql.Open("sqlite3", dataPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	err = models.MigrateDB(p.data)
	if err != nil {
		return nil, fmt.Errorf("migrate db schema: %w", err)
	}
	return &emptypb.Empty{}, nil
}

func (p *Plugin) Query(srv v1.Plugin_QueryServer) error {
	return nil
}

func (p *Plugin) Close(ctx context.Context, req *emptypb.Empty) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, p.data.Close()
}

func (p *Plugin) Store(ctx context.Context, log *v1.StoreLogRequest) (*v1.RaftApplyResponse, error) {
	p.datamux.Lock()
	defer p.datamux.Unlock()
	defer p.currentTerm.Store(log.GetTerm())
	defer p.lastAppliedIndex.Store(log.GetIndex())
	context.LoggerFrom(ctx).Debug("storing log", "index", log.GetIndex(), "term", log.GetTerm())
	return raftlogs.Apply(ctx, p.data, log.GetLog()), nil
}

func (p *Plugin) RestoreSnapshot(ctx context.Context, snapshot *v1.DataSnapshot) (*emptypb.Empty, error) {
	p.datamux.Lock()
	defer p.datamux.Unlock()
	defer p.currentTerm.Store(snapshot.GetTerm())
	defer p.lastAppliedIndex.Store(snapshot.GetIndex())
	context.LoggerFrom(ctx).Info("restoring snapshot", "index", snapshot.GetIndex(), "term", snapshot.GetTerm())
	snapshotter := snapshots.New(p.data)
	return &emptypb.Empty{}, snapshotter.Restore(ctx, io.NopCloser(bytes.NewReader(snapshot.GetData())))
}

func (p *Plugin) Allocate(ctx context.Context, r *v1.AllocateIPRequest) (*v1.AllocatedIP, error) {
	p.datamux.Lock()
	defer p.datamux.Unlock()
	switch r.GetVersion() {
	case v1.AllocateIPRequest_IP_VERSION_4:
		return p.allocateV4(ctx, r)
	case v1.AllocateIPRequest_IP_VERSION_6:
		return p.allocateV6(ctx, r)
	default:
		return nil, fmt.Errorf("unsupported IP version: %v", r.GetVersion())
	}
}

func (p *Plugin) allocateV4(ctx context.Context, r *v1.AllocateIPRequest) (*v1.AllocatedIP, error) {
	globalPrefix, err := netip.ParsePrefix(r.GetSubnet())
	if err != nil {
		return nil, fmt.Errorf("parse subnet: %w", err)
	}
	allocated, err := models.New(p.data).ListAllocatedIPv4(ctx)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("list allocated IPv4s: %w", err)
	}
	allocatedSet, err := toPrefixSet(allocated)
	if err != nil {
		return nil, fmt.Errorf("convert allocated IPv4s to set: %w", err)
	}
	prefix, err := next32(globalPrefix, allocatedSet)
	if err != nil {
		return nil, fmt.Errorf("find next available IPv4: %w", err)
	}
	return &v1.AllocatedIP{
		Ip: prefix.String(),
	}, nil
}

func (p *Plugin) allocateV6(ctx context.Context, r *v1.AllocateIPRequest) (*v1.AllocatedIP, error) {
	globalPrefix, err := netip.ParsePrefix(r.GetSubnet())
	if err != nil {
		return nil, fmt.Errorf("parse subnet: %w", err)
	}
	prefix, err := util.Random64(globalPrefix)
	if err != nil {
		return nil, fmt.Errorf("random IPv6: %w", err)
	}
	return &v1.AllocatedIP{
		Ip: prefix.String(),
	}, nil
}

func (p *Plugin) Release(context.Context, *v1.ReleaseIPRequest) (*emptypb.Empty, error) {
	// No-op, we don't actually track leases explicitly
	return &emptypb.Empty{}, nil
}

func next32(cidr netip.Prefix, set map[netip.Prefix]struct{}) (netip.Prefix, error) {
	ip := cidr.Addr().Next()
	for cidr.Contains(ip) {
		prefix := netip.PrefixFrom(ip, 32)
		if _, ok := set[prefix]; !ok {
			return prefix, nil
		}
		ip = ip.Next()
	}
	return netip.Prefix{}, fmt.Errorf("no more addresses in %s", cidr)
}

func toPrefixSet(addrs []sql.NullString) (map[netip.Prefix]struct{}, error) {
	set := make(map[netip.Prefix]struct{})
	for _, addr := range addrs {
		if !addr.Valid {
			continue
		}
		ip, err := netip.ParsePrefix(addr.String)
		if err != nil {
			return nil, err
		}
		set[ip] = struct{}{}
	}
	return set, nil
}
