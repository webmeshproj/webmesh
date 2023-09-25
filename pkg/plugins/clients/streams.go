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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/webmeshproj/webmesh/pkg/context"
)

func inProcessQueryPipe(ctx context.Context, server v1.PluginServer) v1.StorageQuerierPlugin_InjectQuerierClient {
	// TODO: Make this configurable
	schan := make(chan *v1.PluginQuery, 100)
	rchan := make(chan *v1.PluginQueryResult, 100)
	ctx, cancel := context.WithCancel(ctx)
	srv := &inProcessStreamServer[v1.PluginQuery, v1.PluginQueryResult]{ctx, schan, rchan}
	cli := &inProcessStreamClient[v1.PluginQuery, v1.PluginQueryResult]{ctx, cancel, schan, rchan}
	go func() {
		defer cancel()
		err := server.(v1.StorageQuerierPluginServer).InjectQuerier(srv)
		if err != nil {
			if err != io.EOF && err != context.Canceled && status.Code(err) != codes.Unimplemented {
				context.LoggerFrom(ctx).Error("error in plugin query", "error", err)
			}
		}
	}()
	return cli
}

type inProcessStreamClient[REQ, RESP any] struct {
	ctx    context.Context
	cancel context.CancelFunc
	schan  chan *REQ
	rchan  chan *RESP
}

func (p *inProcessStreamClient[REQ, RESP]) Context() context.Context {
	return p.ctx
}

func (p *inProcessStreamClient[REQ, RESP]) Header() (metadata.MD, error) {
	return nil, nil
}

func (p *inProcessStreamClient[REQ, RESP]) Trailer() metadata.MD {
	return nil
}

func (p *inProcessStreamClient[REQ, RESP]) CloseSend() error {
	p.cancel()
	return nil
}

func (p *inProcessStreamClient[REQ, RESP]) Recv() (*REQ, error) {
	select {
	case <-p.ctx.Done():
		return nil, io.EOF
	case res := <-p.schan:
		return res, nil
	}
}

func (p *inProcessStreamClient[REQ, RESP]) RecvMsg(m interface{}) error {
	return errors.New("not implemented")
}

func (p *inProcessStreamClient[REQ, RESP]) Send(in *RESP) error {
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

func (p *inProcessStreamClient[REQ, RESP]) SendMsg(m interface{}) error {
	return p.Send(m.(*RESP))
}

type inProcessStreamServer[REQ, RESP any] struct {
	ctx   context.Context
	schan chan *REQ
	rchan chan *RESP
}

func (p *inProcessStreamServer[REQ, RESP]) Context() context.Context {
	return p.ctx
}

func (p *inProcessStreamServer[REQ, RESP]) SetHeader(metadata.MD) error {
	return nil
}

func (p *inProcessStreamServer[REQ, RESP]) SendHeader(m metadata.MD) error {
	return nil
}

func (p *inProcessStreamServer[REQ, RESP]) SetTrailer(metadata.MD) {
}

func (p *inProcessStreamServer[REQ, RESP]) Send(in *REQ) error {
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

func (p *inProcessStreamServer[REQ, RESP]) SendMsg(m interface{}) error {
	return p.Send(m.(*REQ))
}

func (p *inProcessStreamServer[REQ, RESP]) Recv() (*RESP, error) {
	select {
	case <-p.ctx.Done():
		return nil, io.EOF
	case res := <-p.rchan:
		return res, nil
	}
}

func (p *inProcessStreamServer[REQ, RESP]) RecvMsg(m interface{}) error {
	return errors.New("not implemented")
}
