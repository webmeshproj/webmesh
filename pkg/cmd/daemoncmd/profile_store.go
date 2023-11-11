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

package daemoncmd

import (
	"fmt"
	"sync"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/providers/backends/badgerdb"
)

// ProfileStore manages the storage of connection profiles.
type ProfileStore interface {
	// Put stores or updates a profile.
	Put(ctx context.Context, id ProfileID, profile Profile) error
	// Get retrieves a profile.
	Get(ctx context.Context, id ProfileID) (Profile, error)
	// List lists all profiles.
	List(ctx context.Context) (Profiles, error)
	// ListProfileIDs lists all profile IDs.
	ListProfileIDs(ctx context.Context) (ProfileIDs, error)
	// Delete deletes a profile.
	Delete(ctx context.Context, id ProfileID) error
	// Close closes the store.
	Close() error
}

// NewProfileStore returns a new ProfileStore. If diskPath is an empty
// string, an in-memory store is returned.
func NewProfileStore(diskPath string) (ProfileStore, error) {
	var st storage.MeshStorage
	var err error
	if diskPath != "" {
		st, err = badgerdb.New(badgerdb.Options{
			DiskPath:   diskPath,
			SyncWrites: true,
		})
	} else {
		st, err = badgerdb.NewInMemory(badgerdb.Options{})
	}
	if err != nil {
		return nil, fmt.Errorf("setup storage: %w", err)
	}
	return &profileStore{st: st}, nil
}

type profileStore struct {
	st storage.MeshStorage
	mu sync.RWMutex
}

func (s *profileStore) Put(ctx context.Context, id ProfileID, profile Profile) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := profile.MarshalProto()
	if err != nil {
		return fmt.Errorf("marshal profile: %w", err)
	}
	err = s.st.PutValue(ctx, id.StorageKey(ctx), data, 0)
	if err != nil {
		return fmt.Errorf("write profile to storage: %w", err)
	}
	return nil
}

func (s *profileStore) Get(ctx context.Context, id ProfileID) (Profile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var profile Profile
	data, err := s.st.GetValue(ctx, id.StorageKey(ctx))
	if err != nil {
		return profile, fmt.Errorf("read profile from storage: %w", err)
	}
	err = profile.UnmarshalProto(data)
	if err != nil {
		return profile, fmt.Errorf("unmarshal profile: %w", err)
	}
	return profile, nil
}

func (s *profileStore) List(ctx context.Context) (Profiles, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	profiles := make(Profiles)
	err := s.st.IterPrefix(ctx, NamespacedPrefixFromContext(ctx), func(key, value []byte) error {
		var profile Profile
		err := profile.UnmarshalProto(value)
		if err != nil {
			return fmt.Errorf("unmarshal profile: %w", err)
		}
		profiles[ProfileIDFromKey(key)] = profile
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("iterate profiles: %w", err)
	}
	return profiles, nil
}

func (s *profileStore) ListProfileIDs(ctx context.Context) (ProfileIDs, error) {
	var ids ProfileIDs
	keys, err := s.st.ListKeys(ctx, NamespacedPrefixFromContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("list profile keys: %w", err)
	}
	for _, key := range keys {
		ids = append(ids, ProfileIDFromKey(key))
	}
	return ids, nil
}

func (s *profileStore) Delete(ctx context.Context, id ProfileID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.st.Delete(ctx, id.StorageKey(ctx))
	if err != nil {
		return fmt.Errorf("delete profile from storage: %w", err)
	}
	return nil
}

func (s *profileStore) Close() error {
	return s.st.Close()
}
