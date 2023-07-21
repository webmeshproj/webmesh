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
	"errors"
	"io"

	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/webmeshproj/node/pkg/context"
)

// NewInProcessClient creates a plugin client from a built-in plugin server.
func NewInProcessClient(plugin v1.PluginServer) *inProcessPlugin {
	return &inProcessPlugin{plugin}
}

type inProcessPlugin struct {
	server v1.PluginServer
}

func (p *inProcessPlugin) GetInfo(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*v1.PluginInfo, error) {
	return p.server.GetInfo(ctx, in)
}

func (p *inProcessPlugin) Configure(ctx context.Context, in *v1.PluginConfiguration, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	return p.server.Configure(ctx, in)
}

func (p *inProcessPlugin) Query(ctx context.Context, opts ...grpc.CallOption) (v1.Plugin_QueryClient, error) {
	schan := make(chan *v1.PluginSQLQuery)
	rchan := make(chan *v1.PluginSQLQueryResult)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	srv := &inProcessQueryServer{ctx, schan, rchan}
	cli := &inProcessQueryClient{ctx, cancel, schan, rchan}
	return cli, p.server.Query(srv)
}

type inProcessQueryClient struct {
	ctx    context.Context
	cancel context.CancelFunc
	schan  chan *v1.PluginSQLQuery
	rchan  chan *v1.PluginSQLQueryResult
}

func (p *inProcessQueryClient) Context() context.Context {
	return p.ctx
}

func (p *inProcessQueryClient) Header() (metadata.MD, error) {
	return nil, nil
}

func (p *inProcessQueryClient) Trailer() metadata.MD {
	return nil
}

func (p *inProcessQueryClient) CloseSend() error {
	p.cancel()
	close(p.rchan)
	close(p.schan)
	return nil
}

func (p *inProcessQueryClient) Recv() (*v1.PluginSQLQuery, error) {
	select {
	case <-p.ctx.Done():
		return nil, io.EOF
	case res := <-p.schan:
		return res, nil
	}
}

func (p *inProcessQueryClient) RecvMsg(m interface{}) error {
	return errors.New("not implemented")
}

func (p *inProcessQueryClient) Send(in *v1.PluginSQLQueryResult) error {
	select {
	case <-p.ctx.Done():
		return p.ctx.Err()
	default:
	}
	select {
	case p.rchan <- in:
	default:
	}
	return nil
}

func (p *inProcessQueryClient) SendMsg(m interface{}) error {
	return p.Send(m.(*v1.PluginSQLQueryResult))
}

type inProcessQueryServer struct {
	ctx   context.Context
	schan chan *v1.PluginSQLQuery
	rchan chan *v1.PluginSQLQueryResult
}

func (p *inProcessQueryServer) Context() context.Context {
	return p.ctx
}

func (p *inProcessQueryServer) SetHeader(metadata.MD) error {
	return nil
}

func (p *inProcessQueryServer) SendHeader(m metadata.MD) error {
	return nil
}

func (p *inProcessQueryServer) SetTrailer(metadata.MD) {
}

func (p *inProcessQueryServer) Send(in *v1.PluginSQLQuery) error {
	select {
	case <-p.ctx.Done():
		return p.ctx.Err()
	default:
	}
	select {
	case p.schan <- in:
	default:
	}
	return nil
}

func (p *inProcessQueryServer) SendMsg(m interface{}) error {
	return p.Send(m.(*v1.PluginSQLQuery))
}

func (p *inProcessQueryServer) Recv() (*v1.PluginSQLQueryResult, error) {
	select {
	case <-p.ctx.Done():
		return nil, io.EOF
	case res := <-p.rchan:
		return res, nil
	}
}

func (p *inProcessQueryServer) RecvMsg(m interface{}) error {
	return errors.New("not implemented")
}

func (p *inProcessPlugin) Close(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	return p.server.Close(context.Background(), &emptypb.Empty{})
}

func (p *inProcessPlugin) Storage() v1.StoragePluginClient {
	cli, ok := p.server.(v1.StoragePluginServer)
	if !ok {
		return nil
	}
	return &inProcessStoragePlugin{cli}
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
	server v1.StoragePluginServer
}

func (p *inProcessStoragePlugin) Store(ctx context.Context, in *v1.StoreLogRequest, opts ...grpc.CallOption) (*v1.RaftApplyResponse, error) {
	return p.server.Store(ctx, in)
}

func (p *inProcessStoragePlugin) RestoreSnapshot(ctx context.Context, in *v1.DataSnapshot, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	return p.server.RestoreSnapshot(ctx, in)
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
