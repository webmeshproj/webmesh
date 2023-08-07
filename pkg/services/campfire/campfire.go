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

// Package campfire provides the campfire service to webmesh clients.
package campfire

import (
	"context"

	"github.com/webmeshproj/webmesh/pkg/storage"
)

// CampFirePrefix is the prefix for campfire service paths.
const CampFirePrefix = "/campfire"

// Options are options for the campfire service.
type Options struct {
	// ListenUDP is the UDP address to listen on.
	ListenUDP string
	// ListenTCP is the TCP address to listen on.
	ListenTCP string
}

// Server is the campfire service.
type Server struct {
	data storage.Storage
}

// NewServer returns a new campfire service.
func NewServer(data storage.Storage, opts Options) *Server {
	return &Server{
		data: data,
	}
}

// ListenAndServe listens and serves the campfire service.
func (s *Server) ListenAndServe() error {
	return nil
}

// Shutdown shuts down the campfire service.
func (s *Server) Shutdown(ctx context.Context) error {
	return nil
}
