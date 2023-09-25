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

package storage

import (
	"context"
	"io"

	v1 "github.com/webmeshproj/api/v1"
)

// Provider is a provider of MeshStorage.
type Provider interface {
	// Close should close the underlying storage as well as any other resources
	// that the provider may have allocated.
	io.Closer

	// Start should start the provider and any resources that it may need.
	Start(context.Context) error
	// Bootstrap should bootstrap the provider for first-time usage.
	Bootstrap(context.Context) error
	// Status returns the status of the storage provider.
	Status() *v1.StorageStatus
	// Storage returns the underlying MeshStorage instance.
	// The provider does not need to guarantee consistency
	// on read operations.
	Storage() MeshStorage
	// Consensus returns the underlying Consensus instance.
	Consensus() Consensus
}

// Consensus is the interface for configuring storage consensus.
type Consensus interface {
	// AddVoter adds a voter to the consensus group.
	AddVoter(context.Context, *v1.StoragePeer) error
	// AddObserver adds an observer to the consensus group.
	AddObserver(context.Context, *v1.StoragePeer) error
	// DemoteVoter demotes a voter to an observer.
	DemoteVoter(context.Context, *v1.StoragePeer) error
	// RemovePeer removes a peer from the consensus group.
	RemovePeer(context.Context, *v1.StoragePeer) error
}
