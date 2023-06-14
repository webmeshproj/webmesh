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

	"github.com/mattn/go-sqlite3"

	"github.com/webmeshproj/node/pkg/meshdb"
	"github.com/webmeshproj/node/pkg/meshdb/models"
	"github.com/webmeshproj/node/pkg/util"
)

// IPAM is the IP address management service.
type IPAM interface {
	// PrefixV4 returns the IPv4 prefix assigned to nodes. This
	// is only populated after the first call to Acquire.
	PrefixV4() netip.Prefix
	// Acquire acquires a lease for the given node.
	Acquire(ctx context.Context, nodeID string) (address netip.Prefix, err error)
	// Release releases the lease for the given node ID.
	Release(ctx context.Context, nodeID string) error
}

// New returns a new IPAM service.
func New(store meshdb.Store) IPAM {
	return &ipam{store: store}
}

type ipam struct {
	store    meshdb.Store
	prefixv4 netip.Prefix
	mux      sync.Mutex
}

// PrefixV4 returns the IPv4 prefix assigned to nodes.
func (i *ipam) PrefixV4() netip.Prefix { return i.prefixv4 }

// Acquire acquires a lease for the given node.
func (i *ipam) Acquire(ctx context.Context, nodeID string) (address netip.Prefix, err error) {
	i.mux.Lock()
	defer i.mux.Unlock()
	rdb := models.New(i.store.ReadDB())
	if !i.prefixv4.IsValid() {
		var ipv4 string
		ipv4, err = models.New(i.store.ReadDB()).GetIPv4Prefix(ctx)
		if err != nil {
			err = fmt.Errorf("get ipv4 prefix: %w", err)
			return
		}
		var prefix netip.Prefix
		prefix, err = netip.ParsePrefix(ipv4)
		if err != nil {
			err = fmt.Errorf("parse prefix: %w", err)
			return
		}
		i.prefixv4 = prefix
	}
	for {
		var allocatedIPv4s []string
		var prefixSet map[netip.Prefix]struct{}
		var allocated netip.Prefix
		var dblease models.Lease

		allocatedIPv4s, err = rdb.ListAllocatedIPv4(ctx)
		if err != nil && err != sql.ErrNoRows {
			err = fmt.Errorf("failed to list allocated IPv4s: %w", err)
			return
		}
		prefixSet, err = util.ToPrefixSet(allocatedIPv4s)
		if err != nil {
			err = fmt.Errorf("failed to convert allocated IPv4s to set: %w", err)
			return
		}
		allocated, err = util.Next32(i.prefixv4, prefixSet)
		if err != nil {
			err = fmt.Errorf("failed to generate random IPv4 prefix: %w", err)
			return
		}
		dblease, err = models.New(i.store.DB()).InsertNodeLease(ctx, models.InsertNodeLeaseParams{
			NodeID:    nodeID,
			Ipv4:      allocated.String(),
			CreatedAt: time.Now().UTC(),
		})
		if err != nil {
			var sqlErr *sqlite3.Error
			if errors.As(err, &sqlErr) && sqlErr.Code == sqlite3.ErrConstraint {
				// We generated a duplicate IPv4 address, try again.
				continue
			}
			err = fmt.Errorf("failed to assign node lease: %w", err)
			return
		}
		if dblease.Ipv4 != allocated.Addr().String() {
			// The database assigned a different IPv4 address, use that
			// instead.
			allocated, err = netip.ParsePrefix(dblease.Ipv4)
			if err != nil {
				err = fmt.Errorf("failed to parse assigned prefix: %w", err)
				return
			}
		}
		// The database will update and return the lease if it already existed
		return allocated, nil
	}
}

// Release releases the lease for the given node ID.
func (i *ipam) Release(ctx context.Context, nodeID string) error {
	i.mux.Lock()
	defer i.mux.Unlock()
	return models.New(i.store.DB()).ReleaseNodeLease(ctx, nodeID)
}
