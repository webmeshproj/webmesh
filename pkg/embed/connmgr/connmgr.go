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

// Package connmgr defines a libp2p webmesh connection manager.
package connmgr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/libp2p/go-libp2p/core/connmgr"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"

	wmbadger "github.com/webmeshproj/webmesh/pkg/storage/badgerdb"
)

// Options are options for the connection manager.
type Options struct {
	// EnableMetrics enables metrics collection.
	EnableMetrics bool
	// Number of goroutines, default value is 8
	NumGoroutines int
	// Logger is the logger to use.
	Logger *slog.Logger
}

// ConnectionManager is a connection manager.
type ConnectionManager struct {
	db  *badger.DB
	log *slog.Logger
	mu  sync.RWMutex
}

// Tag is a tag for a peer.
type Tag struct {
	// Weight is the weight of the tag
	Weight int
	// Protected is true if the tag is protected
	Protected bool
}

func (t Tag) Marshal() ([]byte, error) {
	out, err := json.Marshal(t)
	if err != nil {
		return nil, fmt.Errorf("marshal tag: %w", err)
	}
	return out, nil
}

// New returns a new connection manager.
func New(opts Options) *ConnectionManager {
	numRoutines := 8
	if opts.NumGoroutines > 0 {
		numRoutines = opts.NumGoroutines
	}
	db, err := badger.Open(
		badger.DefaultOptions("").
			WithInMemory(true).
			WithMetricsEnabled(opts.EnableMetrics).
			WithNumGoroutines(numRoutines).
			WithLogger(wmbadger.NewLogAdapter(opts.Logger)),
	)
	if err != nil {
		panic(fmt.Errorf("failed to open in-memory database: %w", err))
	}
	return &ConnectionManager{db: db, log: opts.Logger}
}

// TagPeer tags a peer with a string, associating a weight with the tag.
func (c *ConnectionManager) TagPeer(id peer.ID, tag string, weight int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.log.Debug("Tagging peer", "peer", id.String(), "tag", tag, "weight", weight)
	t := Tag{Weight: weight, Protected: false}
	data, err := t.Marshal()
	if err != nil {
		c.log.Error("Failed to marshal tag", "error", err.Error())
		return
	}
	err = c.db.Update(func(txn *badger.Txn) error {
		key := Tags.PathFor(id).TagFor(tag).Key()
		return txn.Set(key, data)
	})
	if err != nil {
		c.log.Error("Failed to set tag", "error", err.Error())
		return
	}
}

// Untag removes the tagged value from the peer.
func (c *ConnectionManager) UntagPeer(id peer.ID, tag string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.log.Debug("Untagging peer", "peer", id.String(), "tag", tag)
	err := c.db.Update(func(txn *badger.Txn) error {
		key := Tags.PathFor(id).TagFor(tag).Key()
		return txn.Delete(key)
	})
	if err != nil {
		if !errors.Is(err, badger.ErrKeyNotFound) {
			c.log.Error("Failed to delete tag", "error", err.Error())
		}
	}
}

// UpsertTag updates an existing tag or inserts a new one.
//
// The connection manager calls the upsert function supplying the current
// value of the tag (or zero if inexistent). The return value is used as
// the new value of the tag.
func (c *ConnectionManager) UpsertTag(id peer.ID, tag string, upsert func(int) int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.log.Debug("Upserting tag", "peer", id.String(), "tag", tag)
	err := c.db.Update(func(txn *badger.Txn) error {
		key := Tags.PathFor(id).TagFor(tag).Key()
		// Check if the tag exists
		var currentWeight int
		var currentProtection bool
		item, err := txn.Get(key)
		if err != nil && !errors.Is(err, badger.ErrKeyNotFound) {
			return fmt.Errorf("get tag: %w", err)
		}
		if err == nil {
			var t Tag
			err = item.Value(func(val []byte) error {
				return json.Unmarshal(val, &t)
			})
			if err != nil {
				return fmt.Errorf("unmarshal tag: %w", err)
			}
			currentWeight = t.Weight
			currentProtection = t.Protected
		}
		newWeight := upsert(currentWeight)
		t := Tag{Weight: newWeight, Protected: currentProtection}
		data, err := t.Marshal()
		if err != nil {
			return fmt.Errorf("marshal tag: %w", err)
		}
		return txn.Set(key, data)
	})
	if err != nil {
		c.log.Error("Failed to upsert tag", "error", err.Error())
	}
}

// GetTagInfo returns the metadata associated with the peer,
// or nil if no metadata has been recorded for the peer.
func (c *ConnectionManager) GetTagInfo(id peer.ID) *connmgr.TagInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	c.log.Debug("Getting tag info", "peer", id.String())
	return &connmgr.TagInfo{
		FirstSeen: time.Time{},
		Value:     0,
		Tags:      map[string]int{},
		Conns:     map[string]time.Time{},
	}
}

// TrimOpenConns terminates open connections based on an implementation-defined
// heuristic.
func (c *ConnectionManager) TrimOpenConns(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.log.Debug("Trimming open connections")
}

// Notifee returns an implementation that can be called back to inform of
// opened and closed connections.
func (c *ConnectionManager) Notifee() network.Notifiee {
	return &Notifee{c}
}

// Protect protects a peer from having its connection(s) pruned.
//
// Tagging allows different parts of the system to manage protections without interfering with one another.
//
// Calls to Protect() with the same tag are idempotent. They are not refcounted, so after multiple calls
// to Protect() with the same tag, a single Unprotect() call bearing the same tag will revoke the protection.
func (c *ConnectionManager) Protect(id peer.ID, tag string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.log.Debug("Protecting peer", "peer", id.String(), "tag", tag)
	err := c.db.Update(func(txn *badger.Txn) error {
		key := Tags.PathFor(id).TagFor(tag).Key()
		// Fetch the current tag
		item, err := txn.Get(key)
		if err != nil {
			return fmt.Errorf("get tag: %w", err)
		}
		var t Tag
		err = item.Value(func(val []byte) error {
			return json.Unmarshal(val, &t)
		})
		if err != nil {
			return fmt.Errorf("unmarshal tag: %w", err)
		}
		// If the tag is already protected, we don't need to do anything
		if t.Protected {
			c.log.Debug("Peer is already protected", "peer", id.String(), "tag", tag)
			return nil
		}
		// Set the protection flag and save it back
		t.Protected = true
		data, err := t.Marshal()
		if err != nil {
			return fmt.Errorf("marshal tag: %w", err)
		}
		return txn.Set(key, data)
	})
	if err != nil {
		c.log.Error("Failed to protect peer", "error", err.Error())
	}
}

// Unprotect removes a protection that may have been placed on a peer, under the specified tag.
//
// The return value indicates whether the peer continues to be protected after this call, by way of a different tag.
// See notes on Protect() for more info.
func (c *ConnectionManager) Unprotect(id peer.ID, tag string) (protected bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.log.Debug("Unprotecting peer", "peer", id.String(), "tag", tag)
	err := c.db.Update(func(txn *badger.Txn) error {
		key := Tags.PathFor(id).TagFor(tag).Key()
		// Fetch the current tag
		item, err := txn.Get(key)
		if err != nil {
			return fmt.Errorf("get tag: %w", err)
		}
		var t Tag
		err = item.Value(func(val []byte) error {
			return json.Unmarshal(val, &t)
		})
		if err != nil {
			return fmt.Errorf("unmarshal tag: %w", err)
		}
		if !t.Protected {
			// We don't need to do anything
			c.log.Debug("Peer is not protected", "peer", id.String(), "tag", tag)
			return nil
		}
		// Turn off the protection flag
		t.Protected = false
		data, err := t.Marshal()
		if err != nil {
			return fmt.Errorf("marshal tag: %w", err)
		}
		return txn.Set(key, data)
	})
	if err != nil {
		c.log.Error("Failed to unprotect peer", "error", err.Error())
	}
	return c.isProtected(id, "")
}

// IsProtected returns true if the peer is protected for some tag; if the tag is the empty string
// then it will return true if the peer is protected for any tag
func (c *ConnectionManager) IsProtected(id peer.ID, tag string) (protected bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	c.log.Debug("Checking if peer is protected", "peer", id.String(), "tag", tag)
	return c.isProtected(id, tag)
}

func (c *ConnectionManager) isProtected(id peer.ID, tag string) bool {
	var protected bool
	// Iterate over all tags for the peer no matter what.
	// If tag is empty, we return true if any tag is protected.
	err := c.db.View(func(txn *badger.Txn) error {
		prefix := Tags.PathFor(id)
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix.Key()
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			var t Tag
			key := it.Item().Key()
			err := it.Item().Value(func(val []byte) error {
				return json.Unmarshal(val, &t)
			})
			if err != nil {
				// Log the error
				c.log.Error("Failed to unmarshal tag", "error", err.Error())
				if tag == "" {
					// Continue searching
					continue
				}
				// Otherwise, we're done
				return err
			}
			if tag != "" && tag == string(prefix.Trim(key)) {
				protected = t.Protected
				return nil
			} else if tag == "" && t.Protected {
				protected = true
				return nil
			}
		}
		return nil
	})
	if err != nil {
		c.log.Error("Failed to check if peer is protected", "error", err.Error())
	}
	return protected
}

// Close closes the connection manager and stops background processes.
func (c *ConnectionManager) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.log.Debug("Closing connection manager")
	if c.db == nil {
		return nil
	}
	return c.db.Close()
}

// Notifee is a notifee for the connection manager.
type Notifee struct {
	*ConnectionManager
}

// called when network starts listening on an addr
func (n *Notifee) Listen(mw network.Network, addr ma.Multiaddr) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.log.Debug("Listening on addr", "addr", addr.String())
}

// called when network stops listening on an addr
func (n *Notifee) ListenClose(nw network.Network, addr ma.Multiaddr) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.log.Debug("Stopped listening on addr", "addr", addr.String())
}

// called when a connection opened
func (n *Notifee) Connected(nw network.Network, addr network.Conn) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.log.Debug("Connected to peer", "peer", addr.RemotePeer().String())
}

// called when a connection closed
func (n *Notifee) Disconnected(nw network.Network, addr network.Conn) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.log.Debug("Disconnected from peer", "peer", addr.RemotePeer().String())
}
