/*
Copyright 2023.

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

// Package ipam provides IPv4 address management.
package ipam

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"

	"gitlab.com/webmesh/node/pkg/db/raftdb"
	"gitlab.com/webmesh/node/pkg/store"
	"gitlab.com/webmesh/node/pkg/util"
)

// IPAM is the IP address management service.
type IPAM interface {
	// PrefixV4 returns the IPv4 prefix assigned to nodes. This
	// is only populated after the first call to Acquire.
	PrefixV4() netip.Prefix
	// Acquire acquires a lease for the given node.
	Acquire(ctx context.Context, nodeID string) (Lease, error)
	// Release releases the lease.
	Release(context.Context, Lease) error
}

// Lease represents a lease for a node.
type Lease interface {
	// NodeID returns the ID of the node.
	NodeID() string
	// IPv4 returns the IPv4 address of the lease.
	IPv4() netip.Prefix
	// Release releases the lease.
	Release(context.Context) error
}

// New returns a new IPAM service.
func New(store store.Store) IPAM {
	return &ipam{store: store}
}

type ipam struct {
	store    store.Store
	prefixv4 netip.Prefix
	mux      sync.Mutex
}

// PrefixV4 returns the IPv4 prefix assigned to nodes.
func (i *ipam) PrefixV4() netip.Prefix { return i.prefixv4 }

// Acquire acquires a lease for the given node.
func (i *ipam) Acquire(ctx context.Context, nodeID string) (Lease, error) {
	i.mux.Lock()
	defer i.mux.Unlock()
	if !i.prefixv4.IsValid() {
		ipv4, err := raftdb.New(i.store.WeakDB()).GetIPv4Prefix(ctx)
		if err != nil {
			return nil, fmt.Errorf("get ipv4 prefix: %w", err)
		}
		prefix, err := netip.ParsePrefix(ipv4)
		if err != nil {
			return nil, fmt.Errorf("parse prefix: %w", err)
		}
		i.prefixv4 = prefix
	}
	for {
		allocatedIPv4s, err := raftdb.New(i.store.WeakDB()).ListAllocatedIPv4(ctx)
		if err != nil && err != sql.ErrNoRows {
			return nil, fmt.Errorf("failed to list allocated IPv4s: %w", err)
		}
		prefixSet, err := util.ToPrefixSet(allocatedIPv4s)
		if err != nil {
			return nil, fmt.Errorf("failed to convert allocated IPv4s to set: %w", err)
		}
		prefixv4, err := util.Next32(i.prefixv4, prefixSet)
		if err != nil {
			return nil, fmt.Errorf("failed to generate random IPv4 prefix: %w", err)
		}
		dblease, err := raftdb.New(i.store.DB()).InsertNodeLease(ctx, raftdb.InsertNodeLeaseParams{
			NodeID:    nodeID,
			Ipv4:      prefixv4.String(),
			CreatedAt: time.Now().UTC(),
		})
		if err != nil {
			var sqlErr *sqlite.Error
			if errors.As(err, &sqlErr) && sqlErr.Code() == sqlite3.SQLITE_CONSTRAINT {
				// We generated a duplicate IPv4 address, try again.
				continue
			}
			return nil, fmt.Errorf("failed to assign node lease: %w", err)
		}
		if dblease.Ipv4 != prefixv4.Addr().String() {
			// The database assigned a different IPv4 address, use that
			// instead.
			prefixv4, err = netip.ParsePrefix(dblease.Ipv4)
			if err != nil {
				return nil, fmt.Errorf("failed to parse assigned prefix: %w", err)
			}
		}
		// The database will renew and return the lease if it already exists.
		return &lease{
			lease:    dblease,
			prefixv4: prefixv4,
			ipam:     i,
		}, nil
	}
}

// Release releases the lease for the given node.
func (i *ipam) Release(ctx context.Context, lease Lease) error {
	i.mux.Lock()
	defer i.mux.Unlock()
	return raftdb.New(i.store.DB()).ReleaseNodeLease(ctx, lease.NodeID())
}

type lease struct {
	lease    raftdb.Lease
	prefixv4 netip.Prefix
	ipam     *ipam
}

func (l *lease) NodeID() string     { return l.lease.NodeID }
func (l *lease) IPv4() netip.Prefix { return l.prefixv4 }

func (l *lease) Release(ctx context.Context) error {
	return l.ipam.Release(ctx, l)
}
