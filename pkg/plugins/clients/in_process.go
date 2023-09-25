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
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/webmeshproj/webmesh/pkg/context"
)

// NewInProcessClient creates a plugin client from a built-in plugin server.
func NewInProcessClient(plugin v1.PluginServer) *inProcessPlugin {
	return &inProcessPlugin{server: plugin}
}

type inProcessPlugin struct {
	server      v1.PluginServer
	queryStream v1.StorageQuerierPlugin_InjectQuerierClient
}

func (p *inProcessPlugin) GetInfo(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*v1.PluginInfo, error) {
	return p.server.GetInfo(ctx, in)
}

func (p *inProcessPlugin) Configure(ctx context.Context, in *v1.PluginConfiguration, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	return p.server.Configure(ctx, in)
}

func (p *inProcessPlugin) Close(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	if p.queryStream != nil {
		err := p.queryStream.CloseSend()
		if err != nil {
			context.LoggerFrom(ctx).Error("error closing query stream", "error", err)
		}
	}
	return p.server.Close(ctx, &emptypb.Empty{})
}

func (p *inProcessPlugin) Storage() v1.StorageQuerierPluginClient {
	_, ok := p.server.(v1.StorageQuerierPluginServer)
	if !ok {
		return nil
	}
	return &inProcessStoragePlugin{p}
}

func (p *inProcessPlugin) Auth() v1.AuthPluginClient {
	cli, ok := p.server.(v1.AuthPluginServer)
	if !ok {
		return nil
	}
	return &inProcessAuthPlugin{cli}
}

func (p *inProcessPlugin) Events() v1.WatchPluginClient {
	cli, ok := p.server.(v1.WatchPluginServer)
	if !ok {
		return nil
	}
	return &inProcessWatchPlugin{cli}
}

func (p *inProcessPlugin) IPAM() v1.IPAMPluginClient {
	cli, ok := p.server.(v1.IPAMPluginServer)
	if !ok {
		return nil
	}
	return &inProcessIPAMPlugin{cli}
}

type inProcessStoragePlugin struct {
	*inProcessPlugin
}

func (p *inProcessStoragePlugin) InjectQuerier(ctx context.Context, opts ...grpc.CallOption) (v1.StorageQuerierPlugin_InjectQuerierClient, error) {
	p.queryStream = inProcessQueryPipe(ctx, p.server)
	return p.queryStream, nil
}

type inProcessAuthPlugin struct {
	server v1.AuthPluginServer
}

func (p *inProcessAuthPlugin) Authenticate(ctx context.Context, in *v1.AuthenticationRequest, opts ...grpc.CallOption) (*v1.AuthenticationResponse, error) {
	return p.server.Authenticate(ctx, in)
}

type inProcessWatchPlugin struct {
	server v1.WatchPluginServer
}

func (p *inProcessWatchPlugin) Emit(ctx context.Context, in *v1.Event, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	return p.server.Emit(ctx, in)
}

type inProcessIPAMPlugin struct {
	server v1.IPAMPluginServer
}

func (p *inProcessIPAMPlugin) Allocate(ctx context.Context, in *v1.AllocateIPRequest, opts ...grpc.CallOption) (*v1.AllocatedIP, error) {
	return p.server.Allocate(ctx, in)
}

func (p *inProcessIPAMPlugin) Release(ctx context.Context, in *v1.ReleaseIPRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	return p.server.Release(ctx, in)
}
