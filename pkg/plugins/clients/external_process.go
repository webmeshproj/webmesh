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
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"

	v1 "github.com/webmeshproj/api/go/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/webmeshproj/webmesh/pkg/context"
)

// NewExternalProcessClient creates a new plugin client for an external plugin process.
func NewExternalProcessClient(ctx context.Context, path string) (PluginClient, error) {
	p := &externalProcessPlugin{path: path}
	return p, p.start(ctx)
}

type externalProcessPlugin struct {
	path string
	cmd  *exec.Cmd
	mux  sync.Mutex
	cli  v1.PluginClient
	conn *grpc.ClientConn
}

func (p *externalProcessPlugin) GetInfo(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*v1.PluginInfo, error) {
	return p.cli.GetInfo(ctx, in)
}

func (p *externalProcessPlugin) Configure(ctx context.Context, in *v1.PluginConfiguration, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	return p.cli.Configure(ctx, in)
}

func (p *externalProcessPlugin) Close(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	p.mux.Lock()
	defer p.mux.Unlock()
	errs := make([]error, 0, 3)
	if p.cli != nil {
		if _, err := p.cli.Close(ctx, in); err != nil {
			errs = append(errs, err)
		}
	}
	if p.conn != nil {
		if err := p.conn.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if p.cmd != nil && p.cmd.ProcessState == nil {
		if err := p.cmd.Process.Kill(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("close: %v", errs)
	}
	return &emptypb.Empty{}, nil
}

func (p *externalProcessPlugin) Storage() v1.StorageQuerierPluginClient {
	return v1.NewStorageQuerierPluginClient(p.conn)
}

func (p *externalProcessPlugin) Auth() v1.AuthPluginClient {
	return v1.NewAuthPluginClient(p.conn)
}

func (p *externalProcessPlugin) Events() v1.WatchPluginClient {
	return v1.NewWatchPluginClient(p.conn)
}

func (p *externalProcessPlugin) IPAM() v1.IPAMPluginClient {
	return v1.NewIPAMPluginClient(p.conn)
}

// checkProcess checks if the process is running and restarts it if it is not.
func (p *externalProcessPlugin) checkProcess(ctx context.Context) error {
	p.mux.Lock()
	defer p.mux.Unlock()
	if p.cmd.ProcessState != nil {
		if p.conn != nil {
			_ = p.conn.Close()
		}
		_, ok := ctx.Deadline()
		if !ok {
			var cancel context.CancelFunc
			ctx, cancel = context.WithDeadline(ctx, time.Now().Add(5*time.Second))
			defer cancel()
		}
		return p.start(ctx)
	}
	return nil
}

// start starts the plugin server.
func (p *externalProcessPlugin) start(ctx context.Context) error {
	r, w, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("create pipe: %w", err)
	}
	defer r.Close()
	defer w.Close()
	p.cmd = exec.Command(p.path, "--broadcast-fd", strconv.Itoa(int(w.Fd())))
	err = p.cmd.Start()
	if err != nil {
		return fmt.Errorf("start plugin: %w", err)
	}
	// Wait for the address to be written to the pipe.
	b := bufio.NewReader(r)
	if deadline, ok := ctx.Deadline(); ok {
		err = r.SetReadDeadline(deadline)
		if err != nil {
			return fmt.Errorf("set read deadline: %w", err)
		}
	}
	addr, err := b.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read address: %w", err)
	}
	interceptor := func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		if err := p.checkProcess(ctx); err != nil {
			return err
		}
		return invoker(ctx, method, req, reply, p.conn, opts...)
	}
	p.conn, err = grpc.DialContext(ctx, addr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithUnaryInterceptor(interceptor))
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	p.cli = v1.NewPluginClient(p.conn)
	return nil
}
