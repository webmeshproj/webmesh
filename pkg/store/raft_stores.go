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

package store

import (
	"io"

	"github.com/hashicorp/raft"
)

type LogStoreCloser interface {
	io.Closer
	raft.LogStore
}

type StableStoreCloser interface {
	io.Closer
	raft.StableStore
}

type monotonicLogStore struct{ raft.LogStore }

var _ = raft.MonotonicLogStore(&monotonicLogStore{})

func (m *monotonicLogStore) IsMonotonic() bool {
	return true
}

func newInmemStore() *inMemoryCloser {
	return &inMemoryCloser{raft.NewInmemStore()}
}

type inMemoryCloser struct {
	*raft.InmemStore
}

func (i *inMemoryCloser) Close() error {
	return nil
}
