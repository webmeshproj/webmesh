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

package plugins

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"

	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/webmeshproj/node/pkg/context"
)

type PluginClientCloser interface {
	v1.PluginClient
	io.Closer
}

// inProcessClient creates a plugin client from a plugin server.
func inProcessClient(plugin v1.PluginServer) *inProcessPlugin {
	return &inProcessPlugin{plugin}
}

type inProcessPlugin struct {
	server v1.PluginServer
}

// GetInfo returns the information for the plugin.
func (p *inProcessPlugin) GetInfo(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*v1.PluginInfo, error) {
	return p.server.GetInfo(ctx, in)
}

// Configure configures the plugin.
func (p *inProcessPlugin) Configure(ctx context.Context, in *v1.PluginConfiguration, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	return p.server.Configure(ctx, in)
}

// Store applies a raft log entry to the store.
func (p *inProcessPlugin) Store(ctx context.Context, in *v1.StoreLogRequest, opts ...grpc.CallOption) (*v1.RaftApplyResponse, error) {
	return p.server.Store(ctx, in)
}

// RestoreSnapshot restores a snapshot.
func (p *inProcessPlugin) RestoreSnapshot(ctx context.Context, in *v1.DataSnapshot, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	return p.server.RestoreSnapshot(ctx, in)
}

// Authenticate authenticates a request.
func (p *inProcessPlugin) Authenticate(ctx context.Context, in *v1.AuthenticationRequest, opts ...grpc.CallOption) (*v1.AuthenticationResponse, error) {
	return p.server.Authenticate(ctx, in)
}

// Emit emits a watch event.
func (p *inProcessPlugin) Emit(ctx context.Context, in *v1.Event, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	return p.server.Emit(ctx, in)
}

func (p *inProcessPlugin) Close() error { return nil }

type externalProcessPlugin struct {
	path string
	cmd  *exec.Cmd
	mux  sync.Mutex
	cli  v1.PluginClient
	conn *grpc.ClientConn
}

func newExternalProcess(ctx context.Context, path string) (*externalProcessPlugin, error) {
	p := &externalProcessPlugin{path: path}
	return p, p.start(ctx)
}

// GetInfo returns the information for the plugin.
func (p *externalProcessPlugin) GetInfo(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*v1.PluginInfo, error) {
	if err := p.checkProcess(ctx); err != nil {
		return nil, err
	}
	return p.cli.GetInfo(ctx, in)
}

// Configure configures the plugin.
func (p *externalProcessPlugin) Configure(ctx context.Context, in *v1.PluginConfiguration, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	if err := p.checkProcess(ctx); err != nil {
		return nil, err
	}
	return p.cli.Configure(ctx, in)
}

// Store applies a raft log entry to the store.
func (p *externalProcessPlugin) Store(ctx context.Context, in *v1.StoreLogRequest, opts ...grpc.CallOption) (*v1.RaftApplyResponse, error) {
	if err := p.checkProcess(ctx); err != nil {
		return nil, err
	}
	return p.cli.Store(ctx, in)
}

// RestoreSnapshot restores a snapshot.
func (p *externalProcessPlugin) RestoreSnapshot(ctx context.Context, in *v1.DataSnapshot, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	if err := p.checkProcess(ctx); err != nil {
		return nil, err
	}
	return p.cli.RestoreSnapshot(ctx, in)
}

// Authenticate authenticates a request.
func (p *externalProcessPlugin) Authenticate(ctx context.Context, in *v1.AuthenticationRequest, opts ...grpc.CallOption) (*v1.AuthenticationResponse, error) {
	if err := p.checkProcess(ctx); err != nil {
		return nil, err
	}
	return p.cli.Authenticate(ctx, in)
}

// Emit emits a watch event.
func (p *externalProcessPlugin) Emit(ctx context.Context, in *v1.Event, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	if err := p.checkProcess(ctx); err != nil {
		return nil, err
	}
	return p.cli.Emit(ctx, in)
}

func (p *externalProcessPlugin) Close() error {
	p.mux.Lock()
	defer p.mux.Unlock()
	errs := make([]error, 0, 2)
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
		return fmt.Errorf("close: %v", errs)
	}
	return nil
}

// checkProcess checks if the process is running and restarts it if it is not.
func (p *externalProcessPlugin) checkProcess(ctx context.Context) error {
	p.mux.Lock()
	defer p.mux.Unlock()
	if p.cmd.ProcessState != nil {
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
	p.conn, err = grpc.DialContext(ctx, addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	p.cli = v1.NewPluginClient(p.conn)
	return nil
}

type externalServerPlugin struct {
	v1.PluginClient
	conn *grpc.ClientConn
}

func newExternalServer(ctx context.Context, cfg *Config) (*externalServerPlugin, error) {
	// TODO: support TLS
	var opt grpc.DialOption
	if cfg.Insecure {
		opt = grpc.WithTransportCredentials(insecure.NewCredentials())
	} else {
		var tlsConfig tls.Config
		certPool, err := x509.SystemCertPool()
		if err != nil {
			certPool = x509.NewCertPool()
		}
		if cfg.TLSCAFile != "" {
			caCert, err := os.ReadFile(cfg.TLSCAFile)
			if err != nil {
				return nil, fmt.Errorf("read CA file: %w", err)
			}
			if ok := certPool.AppendCertsFromPEM(caCert); !ok {
				return nil, fmt.Errorf("append CA cert: %w", err)
			}
		}
		tlsConfig.RootCAs = certPool
		if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
			cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
			if err != nil {
				return nil, fmt.Errorf("load cert: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}
		if cfg.TLSSkipVerify {
			tlsConfig.InsecureSkipVerify = true
		}
		opt = grpc.WithTransportCredentials(credentials.NewTLS(&tlsConfig))
	}
	c, err := grpc.DialContext(ctx, cfg.Server, opt)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	return &externalServerPlugin{v1.NewPluginClient(c), c}, nil
}

func (p *externalServerPlugin) Close() error {
	return p.conn.Close()
}
