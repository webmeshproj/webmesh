//go:build !wasm

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
	"strings"

	"github.com/nutsdb/nutsdb"

	"github.com/webmeshproj/webmesh/pkg/storage"
)

// Options are the options for creating a new NutsDB storage.
type Options struct {
	// InMemory specifies whether to use an in-memory storage.
	InMemory bool
	// DiskPath is the path to use for disk storage.
	DiskPath string
}

// New creates a new NutsDB storage.
func New(opts Options) (storage.DualStorage, error) {
	if opts.InMemory {
		return newInMemoryStorage()
	}
	if opts.DiskPath == "" {
		return nil, errors.New("disk path must be specified")
	}
	return newDiskStorage(opts.DiskPath)
}

const (
	meshStoreBucket   = "mesh-storage"
	logStoreBucket    = "raft-log"
	stableStoreBucket = "raft-stable"
)

// IsNotFound returns true if the error is a not found error.
func IsNotFound(err error) bool {
	// These guys need help with their error management.
	return nutsdb.IsBucketNotFound(err) ||
		nutsdb.IsBucketEmpty(err) ||
		nutsdb.IsKeyEmpty(err) ||
		nutsdb.IsKeyNotFound(err) ||
		nutsdb.IsPrefixScan(err) ||
		nutsdb.IsPrefixSearchScan(err) ||
		errors.Is(err, nutsdb.ErrBucket) ||
		errors.Is(err, nutsdb.ErrNotFoundBucket) ||
		errors.Is(err, nutsdb.ErrPrefixScan) ||
		strings.Contains(err.Error(), "not found")
}

// IgnoreNotFound returns nil if the error is a not found error.
func IgnoreNotFound(err error) error {
	if err == nil {
		return nil
	}
	if IsNotFound(err) {
		return nil
	}
	return err
}
