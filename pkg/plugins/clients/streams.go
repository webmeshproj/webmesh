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
	"google.golang.org/grpc/metadata"

	"github.com/webmeshproj/node/pkg/context"
)

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
