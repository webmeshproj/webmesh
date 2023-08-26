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

// Package discovery contains facilities for discovering peers in order to join a mesh.
package discovery

import (
	"context"
	"io"
)

// Discovery is the interface for discovering peers in order to join a mesh.
// It is used both by peers announcing for others to join and by peers joining a mesh.
type Discovery interface {
	// Start starts the discovery service.
	Start(context.Context) error
	// Stop stops the discovery service.
	Stop() error
	// Accept returns a connection to a peer.
	// TODO: This needs to be hooked into any configured authentication mechanism.
	Accept() (io.ReadWriteCloser, error)
}
