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

// Package dashboard contains a service that serves a web dashboard.
// nolint
package dashboard

import (
	"crypto/tls"
	"embed"
	"fmt"
	"io/fs"
	"net/http"
	"strings"

	"github.com/improbable-eng/grpc-web/go/grpcweb"
	"google.golang.org/grpc"
)

//go:generate bash -xc "cd app; yarn ; yarn build"

//go:embed app/dist/spa
var staticFiles embed.FS

// Options contains the options for the dashboard service.
type Options struct {
	// ListenAddress is the address to listen on.
	ListenAddress string
	// TLSCertFile is the path to a certificate file to use for TLS.
	TLSCertFile string
	// TLSKeyFile is the path to a key file to use for TLS.
	TLSKeyFile string
	// Prefix is the prefix to use for the dashboard.
	Prefix string
}

// NewServer returns a new Dashboard Server.
func NewServer(backend *grpc.Server, opts *Options) (*Server, error) {
	mux := http.NewServeMux()
	root := strings.TrimSuffix(opts.Prefix, "/")
	apiRoot := fmt.Sprintf("%s/api/", root)
	staticRoot, err := fs.Sub(staticFiles, "app/dist/spa")
	if err != nil {
		return nil, fmt.Errorf("get static subdirectory: %w", err)
	}
	mux.Handle(apiRoot, http.StripPrefix(apiRoot, grpcweb.WrapServer(backend)))
	mux.Handle(root+"/", http.FileServer(http.FS(staticRoot)))
	srvr := &http.Server{
		Addr:    opts.ListenAddress,
		Handler: mux,
	}
	if opts.TLSCertFile != "" && opts.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(opts.TLSCertFile, opts.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load key pair: %w", err)
		}
		srvr.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
	}
	return &Server{Server: srvr}, nil
}

type Server struct {
	*http.Server
}
