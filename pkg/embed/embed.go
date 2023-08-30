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

// Package embed provides a simplified way to run a webmesh node in-process.
// This will hopefully be completed soon.
package embed

import (
	"github.com/ipld/go-ipld-prime/storage"

	"github.com/webmeshproj/webmesh/pkg/mesh"
	"github.com/webmeshproj/webmesh/pkg/raft"
	"github.com/webmeshproj/webmesh/pkg/services"
	"github.com/webmeshproj/webmesh/pkg/services/meshdns"
)

// WebmeshNode is an embedded webmesh node.
type WebmeshNode interface {
	// Mesh returns the underlying mesh instance.
	Mesh() mesh.Mesh
	// Raft is the underlying Raft instance.
	Raft() raft.Raft
	// Storage is the underlying storage instance.
	Storage() storage.Storage
	// Services returns the underlying services instance
	// if it is running.
	Services() *services.Server
	// MeshDNS returns the underlying MeshDNS instance
	// if it is running.
	MeshDNS() *meshdns.Server
}
