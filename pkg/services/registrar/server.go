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

package registrar

import (
	"context"
	"sync"
	"time"

	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/errors"
)

// StorageDriver is a storage driver for the registrar.
type StorageDriver interface {
	Register(ctx context.Context, key crypto.PublicKey, alias string, validUntil time.Time) (*v1.RegisterResponse, error)
	Lookup(ctx context.Context, req LookupRequest) (*v1.LookupResponse, error)
}

// LookupRequest is a parsed lookup request from the registrar.
type LookupRequest struct {
	Alias string
	ID    string
	Key   crypto.PublicKey
}

// Common errors.
var (
	ErrNotImplemented    = status.Error(codes.Unimplemented, "method not implemensted")
	ErrAliasExists       = status.Error(codes.AlreadyExists, "alias already exists")
	ErrAliasNotFound     = status.Error(codes.NotFound, "alias not found")
	ErrPublicKeyNotFound = status.Error(codes.NotFound, "public key not found")
	ErrIDNotFound        = status.Error(codes.NotFound, "id not found")
)

// Options are options for configuring the registrar server.
type Options struct {
	// StorageDriver is the storage driver to use.
	StorageDriver StorageDriver
}

// Server is the registrar service.
type Server struct {
	v1.UnimplementedRegistrarServer
	driver StorageDriver
}

// NewServer returns a new registrar server.
func NewServer(opts Options) *Server {
	return &Server{
		driver: opts.StorageDriver,
	}
}

// Register is the registrar Register RPC.
func (srv *Server) Register(ctx context.Context, req *v1.RegisterRequest) (*v1.RegisterResponse, error) {
	if req.GetPublicKey() == "" {
		return nil, status.Error(codes.InvalidArgument, "public key required")
	}
	key, err := crypto.DecodePublicKey(req.GetPublicKey())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid public key: %v", err)
	}
	if !req.GetExpiry().IsValid() {
		return nil, status.Error(codes.InvalidArgument, "invalid expiry")
	}
	expiry := req.GetExpiry().AsTime()
	if expiry.IsZero() {
		// Set to the default one year
		expiry = time.Now().UTC().Add(time.Hour * 24 * 365)
	}
	return srv.driver.Register(ctx, key, req.GetAlias(), expiry)
}

// Lookup is the registrar Lookup RPC.
func (srv *Server) Lookup(ctx context.Context, req *v1.LookupRequest) (*v1.LookupResponse, error) {
	var opts LookupRequest
	switch {
	case req.GetAlias() != "":
		opts.Alias = req.GetAlias()
	case req.GetId() != "":
		opts.ID = req.GetId()
	case req.GetPublicKey() != "":
		key, err := crypto.DecodePublicKey(req.GetPublicKey())
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid public key: %v", err)
		}
		opts.Key = key
	}
	return srv.driver.Lookup(ctx, opts)
}

// MeshStorageDriver is a storage driver that uses the underlying mesh storage.
type MeshStorageDriver struct {
	st storage.MeshStorage
	mu sync.RWMutex
}

// NewMeshStorageDriver returns a new mesh storage driver.
func NewMeshStorageDriver(st storage.MeshStorage) StorageDriver {
	return &MeshStorageDriver{
		st: st,
	}
}

var (
	IDPrefix    = []byte("/registrar/id/")
	AliasPrefix = []byte("/registrar/alias/")
)

// Register is the registrar Register RPC.
func (st *MeshStorageDriver) Register(ctx context.Context, key crypto.PublicKey, alias string, validUntil time.Time) (*v1.RegisterResponse, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if alias == "" {
		alias = key.ID()
	}
	idKey := append(IDPrefix, []byte(key.ID())...)
	aliasKey := append(AliasPrefix, []byte(alias)...)
	if _, err := st.st.GetValue(ctx, aliasKey); err == nil {
		return nil, ErrAliasExists
	} else if !errors.IsNotFound(err) {
		return nil, err
	}
	// Write all the values.
	encoded, err := key.Encode()
	if err != nil {
		return nil, err
	}
	ttl := validUntil.Sub(time.Now().UTC())
	if err := st.st.PutValue(ctx, aliasKey, []byte(encoded), ttl); err != nil {
		return nil, err
	}
	if err := st.st.PutValue(ctx, idKey, []byte(encoded), ttl); err != nil {
		return nil, err
	}
	return &v1.RegisterResponse{
		Id: key.ID(),
	}, nil
}

// Lookup is the registrar Lookup RPC.
func (st *MeshStorageDriver) Lookup(ctx context.Context, req LookupRequest) (*v1.LookupResponse, error) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	switch {
	case req.Alias != "":
		aliasKey := append(AliasPrefix, []byte(req.Alias)...)
		encoded, err := st.st.GetValue(ctx, aliasKey)
		if err != nil {
			if errors.IsNotFound(err) {
				return nil, ErrAliasNotFound
			}
			return nil, err
		}
		key, err := crypto.DecodePublicKey(string(encoded))
		if err != nil {
			return nil, err
		}
		return &v1.LookupResponse{
			Id:        key.ID(),
			PublicKey: string(encoded),
			Alias:     req.Alias,
		}, nil
	case req.ID != "":
		idKey := append(IDPrefix, []byte(req.ID)...)
		encoded, err := st.st.GetValue(ctx, idKey)
		if err != nil {
			if errors.IsNotFound(err) {
				return nil, ErrIDNotFound
			}
			return nil, err
		}
		var alias string
		err = st.st.IterPrefix(ctx, AliasPrefix, func(key, value []byte) error {
			if string(value) == string(encoded) {
				alias = string(key[len(AliasPrefix):])
				return storage.ErrStopIteration
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		return &v1.LookupResponse{
			Id:        req.ID,
			PublicKey: string(encoded),
			Alias:     alias,
		}, nil
	case req.Key != nil:
		idKey := append(IDPrefix, []byte(req.Key.ID())...)
		encoded, err := st.st.GetValue(ctx, idKey)
		if err != nil {
			if errors.IsNotFound(err) {
				return nil, ErrPublicKeyNotFound
			}
			return nil, err
		}
		var alias string
		err = st.st.IterPrefix(ctx, AliasPrefix, func(key, value []byte) error {
			if string(value) == string(encoded) {
				alias = string(key[len(AliasPrefix):])
				return storage.ErrStopIteration
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		return &v1.LookupResponse{
			Id:        req.Key.ID(),
			PublicKey: string(encoded),
			Alias:     alias,
		}, nil
	default:
		return nil, status.Error(codes.InvalidArgument, "alias, id, or public key required")
	}
}
