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

// Package connmgr defines the libp2p webmesh connection manager.
package connmgr

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/connmgr"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/nutsdb/nutsdb/inmemory"

	"github.com/webmeshproj/webmesh/pkg/storage/nutsdb"
)

// Ensure we implement the interfaces.
var _ connmgr.ConnManager = (*ConnMgr)(nil)
var _ network.Notifiee = (*Notifee)(nil)

// ConnMgr is a connection manager that does nothing.
type ConnMgr struct {
	db    *inmemory.DB
	conns map[peer.ID]map[string]network.Conn
	log   *slog.Logger
	mu    sync.RWMutex
}

// Prefix is a prefix for values in the database.
type Prefix string

const (
	// TagPrefix is the prefix for tags.
	TagPrefix Prefix = "tag:"
	// ConnPrefix is the prefix for connections.
	ConnPrefix Prefix = "conn:"
)

func (p Prefix) KeyFor(tag string) []byte {
	return append([]byte(p), []byte(tag)...)
}

// Tag is a string that can be associated with a peer.
type Tag struct {
	Weight    int
	Protected bool
}

// Conn is a connection to a peer.
type Conn struct {
	Raddr   string
	Started time.Time
}

// New returns a new connection manager.
func New(log *slog.Logger) *ConnMgr {
	db, err := inmemory.Open(inmemory.DefaultOptions)
	if err != nil {
		panic(fmt.Errorf("failed to open in-memory database: %w", err))
	}
	return &ConnMgr{
		db:    db,
		conns: map[peer.ID]map[string]network.Conn{},
		log:   log,
	}
}

// TagPeer tags a peer with a string, associating a weight with the tag.
func (c *ConnMgr) TagPeer(p peer.ID, tag string, weight int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := Tag{Weight: weight}
	c.log.Debug("Tagging peer", "peer", p, "tag", t)
	data, err := json.Marshal(t)
	if err != nil {
		c.log.Error("Failed to tag peer", "peer", p, "tag", tag, "weight", weight, "error", err.Error())
		return
	}
	err = c.db.Put(p.String(), TagPrefix.KeyFor(tag), data, 0)
	if err != nil {
		c.log.Error("Failed to tag peer", "peer", p, "tag", tag, "weight", weight, "error", err.Error())
	}
}

// Untag removes the tagged value from the peer.
func (c *ConnMgr) UntagPeer(p peer.ID, tag string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	existing, err := c.getTagByName(p, tag)
	if err != nil {
		if !nutsdb.IsNotFound(err) {
			c.log.Error("Failed to untag peer", "peer", p, "tag", tag, "error", err.Error())
		}
		return
	}
	if !existing.Protected {
		err = c.db.Delete(p.String(), TagPrefix.KeyFor(tag))
		if nutsdb.IgnoreNotFound(err) != nil {
			c.log.Error("Failed to untag peer", "peer", p, "tag", tag, "error", err.Error())
		}
	}
}

// UpsertTag updates an existing tag or inserts a new one.
//
// The connection manager calls the upsert function supplying the current
// value of the tag (or zero if inexistent). The return value is used as
// the new value of the tag.
func (c *ConnMgr) UpsertTag(p peer.ID, tag string, upsert func(int) int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	existing, err := c.getTagByName(p, tag)
	if err != nil {
		if !nutsdb.IsNotFound(err) {
			c.log.Error("Failed to untag peer", "peer", p, "tag", tag, "error", err.Error())
		}
		return
	}
	newWeight := upsert(existing.Weight)
	if newWeight != existing.Weight {
		existing.Weight = newWeight
		data, err := json.Marshal(existing)
		if err != nil {
			c.log.Error("Failed to upsert tag", "peer", p, "tag", tag, "error", err.Error())
			return
		}
		err = c.db.Put(p.String(), TagPrefix.KeyFor(tag), data, 0)
		if err != nil {
			c.log.Error("Failed to upsert tag", "peer", p, "tag", tag, "error", err.Error())
		}
	}
}

// GetTagInfo returns the metadata associated with the peer,
// or nil if no metadata has been recorded for the peer.
func (c *ConnMgr) GetTagInfo(p peer.ID) *connmgr.TagInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	tagInfo := &connmgr.TagInfo{
		FirstSeen: time.Time{},
		Value:     0,
		Tags:      map[string]int{},
		Conns:     map[string]time.Time{},
	}
	tags, _, err := c.db.PrefixScan(p.String(), TagPrefix.KeyFor(""), 0, math.MaxInt)
	if err != nil {
		if !nutsdb.IsNotFound(err) {
			c.log.Error("Failed to get tag info", "peer", p, "error", err.Error())
		}
		return nil
	}
	for _, entry := range tags {
		t, err := decodeTag(entry.Value)
		if err != nil {
			c.log.Error("Failed to get tag info", "peer", p, "error", err.Error())
			continue
		}
		tag := strings.TrimPrefix(string(entry.Key), string(TagPrefix))
		tagInfo.Tags[tag] = t.Weight
	}
	conns, _, err := c.db.PrefixScan(p.String(), ConnPrefix.KeyFor(""), 0, math.MaxInt)
	if err != nil {
		if !nutsdb.IsNotFound(err) {
			c.log.Error("Failed to get tag info", "peer", p, "error", err.Error())
		}
		// We don't have any connections, so we can return early.
		return tagInfo
	}
	for _, entry := range conns {
		conn, err := decodeConn(entry.Value)
		if err != nil {
			c.log.Error("Failed to get tag info", "peer", p, "error", err.Error())
			continue
		}
		tagInfo.Conns[conn.Raddr] = conn.Started
		if tagInfo.FirstSeen.IsZero() || conn.Started.Before(tagInfo.FirstSeen) {
			tagInfo.FirstSeen = conn.Started
		}
	}
	return tagInfo
}

// TrimOpenConns terminates open connections based on an implementation-defined
// heuristic.
func (c *ConnMgr) TrimOpenConns(ctx context.Context) {
	// Iterate all connections, and if the peer is not protected, close the connection.
	c.mu.Lock()
	defer c.mu.Unlock()
	for p, conns := range c.conns {
		if c.isProtected(p, "") {
			continue
		}
		for _, conn := range conns {
			// Delete the connection from the database.
			err := c.db.Delete(p.String(), ConnPrefix.KeyFor(conn.RemoteMultiaddr().String()))
			if nutsdb.IgnoreNotFound(err) != nil {
				c.log.Error("Failed to delete connection", "peer", p, "error", err.Error())
			}
			err = conn.Close()
			if err != nil {
				c.log.Error("Failed to close connection", "peer", p, "error", err.Error())
			}

		}
		delete(c.conns, p)
	}
}

// Notifee returns an implementation that can be called back to inform of
// opened and closed connections.
func (c *ConnMgr) Notifee() network.Notifiee { return &Notifee{c} }

// Protect protects a peer from having its connection(s) pruned.
//
// Tagging allows different parts of the system to manage protections without interfering with one another.
//
// Calls to Protect() with the same tag are idempotent. They are not refcounted, so after multiple calls
// to Protect() with the same tag, a single Unprotect() call bearing the same tag will revoke the protection.
func (c *ConnMgr) Protect(id peer.ID, tag string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	t, err := c.getTagByName(id, tag)
	if err != nil {
		if !nutsdb.IsNotFound(err) {
			c.log.Error("Failed to protect peer", "peer", id, "tag", tag, "error", err.Error())
		}
		return
	}
	t.Protected = true
	data, err := json.Marshal(t)
	if err != nil {
		c.log.Error("Failed to protect peer", "peer", id, "tag", tag, "error", err.Error())
		return
	}
	err = c.db.Put(id.String(), TagPrefix.KeyFor(tag), data, 0)
	if err != nil {
		c.log.Error("Failed to protect peer", "peer", id, "tag", tag, "error", err.Error())
	}
}

// Unprotect removes a protection that may have been placed on a peer, under the specified tag.
//
// The return value indicates whether the peer continues to be protected after this call, by way of a different tag.
// See notes on Protect() for more info.
func (c *ConnMgr) Unprotect(id peer.ID, tag string) (protected bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	t, err := c.getTagByName(id, tag)
	if err != nil {
		if !nutsdb.IsNotFound(err) {
			c.log.Error("Failed to unprotect peer", "peer", id, "tag", tag, "error", err.Error())
		}
		return false
	}
	if t.Protected {
		// Update the tag to be unprotected.
		t.Protected = false
		data, err := json.Marshal(t)
		if err != nil {
			c.log.Error("Failed to unprotect peer", "peer", id, "tag", tag, "error", err.Error())
			return false
		}
		err = c.db.Put(id.String(), TagPrefix.KeyFor(tag), data, 0)
		if err != nil {
			c.log.Error("Failed to unprotect peer", "peer", id, "tag", tag, "error", err.Error())
			return false
		}
	}
	return c.isProtected(id, "")
}

// IsProtected returns true if the peer is protected for some tag; if the tag is the empty string
// then it will return true if the peer is protected for any tag
func (c *ConnMgr) IsProtected(id peer.ID, tag string) (protected bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.isProtected(id, tag)
}

func (c *ConnMgr) isProtected(id peer.ID, tag string) bool {
	if tag != "" {
		t, err := c.getTagByName(id, tag)
		if err != nil {
			if !nutsdb.IsNotFound(err) {
				c.log.Error("Failed to check if peer is protected", "peer", id, "tag", tag, "error", err.Error())
			}
			return false
		}
		return t.Protected
	}
	// Check for any tag that is protecting the peer.
	tags, _, err := c.db.PrefixScan(id.String(), TagPrefix.KeyFor(""), 0, math.MaxInt)
	if err != nil {
		if !nutsdb.IsNotFound(err) {
			c.log.Error("Failed to check if peer is protected", "peer", id, "tag", tag, "error", err.Error())
		}
		return false
	}
	for _, entry := range tags {
		t, err := decodeTag(entry.Value)
		if err != nil {
			c.log.Error("Failed to check if peer is protected", "peer", id, "tag", tag, "error", err.Error())
			continue
		}
		if t.Protected {
			return true
		}
	}
	return false
}

// Close closes the connection manager and stops background processes.
func (c *ConnMgr) Close() error { return nil }

type Notifee struct {
	*ConnMgr
}

// Listen is called when the network starts listening on an addr.
func (n *Notifee) Listen(nw network.Network, raddr ma.Multiaddr) {
	n.mu.Lock()
	defer n.mu.Unlock()
	c := Conn{Raddr: raddr.String(), Started: time.Now()}
	data, err := json.Marshal(c)
	if err != nil {
		n.log.Error("Failed to store connection", "address", raddr.String(), "error", err.Error())
		return
	}
	err = n.db.Put(nw.LocalPeer().String(), ConnPrefix.KeyFor(raddr.String()), data, 0)
	if err != nil {
		n.log.Error("Failed to store connection", "address", raddr.String(), "error", err.Error())
	}
}

// ListenClose is called when the network stops listening on an addr.
func (n *Notifee) ListenClose(nw network.Network, raddr ma.Multiaddr) {
	n.mu.Lock()
	defer n.mu.Unlock()
	err := n.db.Delete(nw.LocalPeer().String(), ConnPrefix.KeyFor(raddr.String()))
	if nutsdb.IgnoreNotFound(err) != nil {
		n.log.Error("Failed to delete connection", "address", raddr.String(), "error", err.Error())
	}
}

// Connected is called when a connection opened.
func (n *Notifee) Connected(nw network.Network, c network.Conn) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.conns[c.RemotePeer()] == nil {
		n.conns[c.RemotePeer()] = map[string]network.Conn{}
	}
	n.conns[c.RemotePeer()][c.RemoteMultiaddr().String()] = c
	remote := c.RemoteMultiaddr().String()
	conn := Conn{Raddr: remote, Started: time.Now()}
	data, err := json.Marshal(conn)
	if err != nil {
		n.log.Error("Failed to store connection", "address", remote, "error", err.Error())
		return
	}
	err = n.db.Put(c.RemotePeer().String(), ConnPrefix.KeyFor(remote), data, 0)
	if err != nil {
		n.log.Error("Failed to store connection", "address", remote, "error", err.Error())
	}
}

// Disconnected is called when a connection closed.
func (n *Notifee) Disconnected(nw network.Network, c network.Conn) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.conns[c.RemotePeer()] != nil {
		delete(n.conns[c.RemotePeer()], c.RemoteMultiaddr().String())
	}
	remote := c.RemoteMultiaddr().String()
	err := n.db.Delete(c.RemotePeer().String(), ConnPrefix.KeyFor(remote))
	if nutsdb.IgnoreNotFound(err) != nil {
		n.log.Error("Failed to delete connection", "address", remote, "error", err.Error())
	}
}

func (c *ConnMgr) getTagByName(p peer.ID, tag string) (Tag, error) {
	existing, err := c.db.Get(p.String(), TagPrefix.KeyFor(tag))
	if err != nil {
		return Tag{}, err
	}
	var t Tag
	if existing != nil {
		return decodeTag(existing.Value)
	}
	return t, nil
}

func decodeTag(value []byte) (Tag, error) {
	var t Tag
	err := json.Unmarshal(value, &t)
	if err != nil {
		return Tag{}, err
	}
	return t, nil
}

func decodeConn(value []byte) (Conn, error) {
	var c Conn
	err := json.Unmarshal(value, &c)
	if err != nil {
		return Conn{}, err
	}
	return c, nil
}
