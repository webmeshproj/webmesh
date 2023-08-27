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

// Package nutsdb implements the storage backends using NutsDB.
package nutsdb

import (
	"errors"

	"github.com/nutsdb/nutsdb"

	"github.com/webmeshproj/webmesh/pkg/storage"
)

// Storage is the NutsDB storage interface. It implements both the mesh and Raft
// storage interfaces.
type Storage interface {
	storage.MeshStorage
	storage.RaftStorage
}

// Options are the options for creating a new NutsDB storage.
type Options struct {
	// InMemory specifies whether to use an in-memory storage.
	InMemory bool
	// DiskPath is the path to use for disk storage.
	DiskPath string
}

const (
	logStoreBucket    = "raft-log"
	stableStoreBucket = "raft-stable"
)

// New creates a new NutsDB storage.
func New(opts Options) (Storage, error) {
	if opts.InMemory {
		return newInMemoryStorage()
	}
	return newDiskStorage(opts.DiskPath)
}

func isKeyNotFoundErr(err error) bool {
	return errors.Is(err, nutsdb.ErrBucket) ||
		errors.Is(err, nutsdb.ErrBucketNotFound) ||
		errors.Is(err, nutsdb.ErrKeyNotFound) ||
		errors.Is(err, nutsdb.ErrPrefixScan)
}
