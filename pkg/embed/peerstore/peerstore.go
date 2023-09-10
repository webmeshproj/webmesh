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

// Package peerstore defines the libp2p webmesh peerstore.
package peerstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/dgraph-io/badger/v4/pb"
	p2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	cryptopb "github.com/libp2p/go-libp2p/core/crypto/pb"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	p2pproto "github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/core/record"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/webmeshproj/webmesh/pkg/crypto"
	wmbadger "github.com/webmeshproj/webmesh/pkg/storage/badgerdb"
	"github.com/webmeshproj/webmesh/pkg/util"
)

// Ensure we implement the interfaces.
var _ peerstore.Peerstore = (*Peerstore)(nil)
var _ peerstore.CertifiedAddrBook = (*Peerstore)(nil)

// Options are options for the peerstore.
type Options struct {
	// EnableMetrics enables metrics collection.
	EnableMetrics bool
	// Number of goroutines, default value is 8
	NumGoroutines int
	// Logger is the logger to use.
	Logger *slog.Logger
}

// New returns a new peerstore.
func New(opts Options) *Peerstore {
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
	return &Peerstore{
		db:          db,
		peermeta:    make(map[peer.ID]map[string]any),
		peerRecords: make(map[peer.ID]PeerRecord),
		log:         opts.Logger,
	}
}

// Peerstore is a libp2p peerstore.
type Peerstore struct {
	db          *badger.DB
	peermeta    map[peer.ID]map[string]any
	peerRecords map[peer.ID]PeerRecord
	log         *slog.Logger
	mu          sync.RWMutex
}

// Key is the data stored for a private or public key.
type Key struct {
	Encoded string
	Type    cryptopb.KeyType
}

// Observation is a latency observation.
type Observation struct {
	// Time is the time the observation was made.
	Time time.Time
	// Latency is the latency observed as a duration string.
	Latency string
}

// PeerRecord is a record of a peer.
type PeerRecord struct {
	Envelope *record.Envelope
	Record   *peer.PeerRecord
	Seq      uint64
	Expires  time.Time
}

// StorageKey is a key prefix for values in the database.
type StorageKey string

const (
	PrivateKeys  StorageKey = "/private-key"
	PublicKeys   StorageKey = "/public-key"
	Multiaddrs   StorageKey = "/multiaddrs"
	Protocols    StorageKey = "/protocols"
	Observations StorageKey = "/observations"
)

func (p StorageKey) Key() []byte { return []byte(p) }

func (p StorageKey) String() string { return string(p) }

func (p StorageKey) PathFor(peer peer.ID) StorageKey {
	return StorageKey("/" + peer.String() + p.String())
}

func (p StorageKey) KeyFor(value string) StorageKey {
	return StorageKey(p.String() + "/" + value)
}

func (p StorageKey) Trim(key []byte) []byte {
	len := len(p)
	if strings.Contains(string(p), string(Multiaddrs)) || strings.Contains(string(p), string(Protocols)) {
		// We need to trim the leading slash.
		len++
	}
	return key[len:]
}

// Close closes the peerstore. This is a no-op.
func (st *Peerstore) Close() error {
	return st.db.Close()
}

// PeerInfo returns a peer.PeerInfo struct for given peer.ID.
// This is a small slice of the information Peerstore has on
// that peer, useful to other services.
func (st *Peerstore) PeerInfo(p peer.ID) peer.AddrInfo {
	addrs := st.Addrs(p)
	return peer.AddrInfo{
		ID:    p,
		Addrs: addrs,
	}
}

// Peers returns all the peer IDs stored across all inner stores.
func (st *Peerstore) Peers() peer.IDSlice {
	st.mu.RLock()
	defer st.mu.RUnlock()
	var peers = make(map[peer.ID]struct{})
	for p := range st.peermeta {
		peers[p] = struct{}{}
	}
	for p := range st.peerRecords {
		peers[p] = struct{}{}
	}
	err := st.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			spl := bytes.Split(it.Item().Key(), []byte("/"))
			if len(spl) < 2 {
				continue
			}
			p, err := peer.Decode(string(spl[1]))
			if err != nil {
				st.log.Error("Failed to decode peer ID", "error", err.Error())
				continue
			}
			peers[p] = struct{}{}
		}
		return nil
	})
	if err != nil {
		st.log.Error("Failed to iterate over database", "error", err.Error())
	}
	var out peer.IDSlice
	for p := range peers {
		out = util.UpsertSlice(out, p)
	}
	return out
}

// RemovePeer removes all data associated with a peer.
func (st *Peerstore) RemovePeer(p peer.ID) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.log.Debug("Removing peer", "peer", p.String())
	// Remove the peer from the list.
	delete(st.peermeta, p)
	delete(st.peerRecords, p)
	// Remove all keys associated with the peer.
	err := st.db.DropPrefix([]byte("/" + p.String()))
	if err != nil {
		st.log.Error("Failed to drop peer from database", "error", err.Error())
	}
}

// AddAddr calls AddAddrs(p, []ma.Multiaddr{addr}, ttl)
func (st *Peerstore) AddAddr(p peer.ID, addr ma.Multiaddr, ttl time.Duration) {
	st.AddAddrs(p, []ma.Multiaddr{addr}, ttl)
}

// AddAddrs gives this AddrBook addresses to use, with a given ttl
// (time-to-live), after which the address is no longer valid.
// If the manager has a longer TTL, the operation is a no-op for that address
func (st *Peerstore) AddAddrs(p peer.ID, addrs []ma.Multiaddr, ttl time.Duration) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.log.Debug("Adding addresses for peer", "peer", p.String(), "addrs", addrs)
	if ttl == peerstore.PermanentAddrTTL {
		ttl = 0
	}
	err := st.db.Update(func(txn *badger.Txn) error {
		path := Multiaddrs.PathFor(p)
		for _, addr := range addrs {
			key := path.KeyFor(addr.String()).Key()
			entry := badger.NewEntry(key, []byte{})
			if ttl > 0 {
				entry = entry.WithTTL(ttl)
			}
			err := txn.SetEntry(entry)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		st.log.Error("Failed to put addresses in database", "error", err.Error())
	}
}

// SetAddr calls mgr.SetAddrs(p, addr, ttl)
func (st *Peerstore) SetAddr(p peer.ID, addr ma.Multiaddr, ttl time.Duration) {
	st.SetAddrs(p, []ma.Multiaddr{addr}, ttl)
}

// SetAddrs sets the ttl on addresses. This clears any TTL there previously.
// This is used when we receive the best estimate of the validity of an address.
func (st *Peerstore) SetAddrs(p peer.ID, addrs []ma.Multiaddr, ttl time.Duration) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.log.Debug("Setting addresses for peer", "peer", p.String(), "addrs", addrs)
	if ttl == peerstore.PermanentAddrTTL {
		ttl = 0
	}
	err := st.db.Update(func(txn *badger.Txn) error {
		path := Multiaddrs.PathFor(p)
		for _, addr := range addrs {
			key := path.KeyFor(addr.String()).Key()
			entry := badger.NewEntry(key, []byte{})
			if ttl > 0 {
				entry = entry.WithTTL(ttl)
			}
			err := txn.SetEntry(entry)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		st.log.Error("Failed to set addresses in database", "error", err.Error())
	}
}

// UpdateAddrs updates the addresses associated with the given peer that have
// the given oldTTL to have the given newTTL.
func (st *Peerstore) UpdateAddrs(p peer.ID, oldTTL time.Duration, newTTL time.Duration) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.log.Debug("Updating addresses for peer", "peer", p.String(), "oldTTL", oldTTL, "newTTL", newTTL)
	err := st.db.Update(func(txn *badger.Txn) error {
		prefix := Multiaddrs.PathFor(p).Key()
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			entry := it.Item()
			if entry.ExpiresAt() == 0 {
				if oldTTL == 0 {
					// Placing a TTL on a record that originally had no TTL.
					st.log.Debug("Updating address", "peer", p.String(),
						"addr", string(entry.Key()),
						"oldTTL", oldTTL,
						"newTTL", newTTL,
					)
					new := badger.NewEntry(entry.Key(), []byte{}).WithTTL(newTTL)
					err := txn.SetEntry(new)
					if err != nil {
						return err
					}
				}
				continue
			}
			// Check if we are updating the TTL
			t := time.Unix(int64(entry.ExpiresAt()), 0)
			ttl := time.Until(t)
			if ttlInRange(ttl, oldTTL-time.Second, oldTTL+time.Second) {
				// Update the TTL.
				st.log.Debug("Updating address", "peer", p.String(),
					"addr", string(entry.Key()),
					"oldTTL", oldTTL,
					"newTTL", newTTL,
				)
				new := badger.NewEntry(entry.Key(), []byte{}).WithTTL(newTTL)
				err := txn.SetEntry(new)
				if err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		st.log.Error("Failed to update addresses in database", "error", err.Error())
	}
}

func ttlInRange(ttl time.Duration, min time.Duration, max time.Duration) bool {
	return ttl >= min && ttl <= max
}

// Addrs returns all known (and valid) addresses for a given peer.
func (st *Peerstore) Addrs(p peer.ID) []ma.Multiaddr {
	st.mu.RLock()
	defer st.mu.RUnlock()
	st.log.Debug("Getting addresses for peer", "peer", p.String())
	var addrs []ma.Multiaddr
	err := st.db.View(func(txn *badger.Txn) error {
		prefix := Multiaddrs.PathFor(p)
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix.Key()
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			addr := prefix.Trim(it.Item().Key())
			ma, err := ma.NewMultiaddr(string(addr))
			if err != nil {
				st.log.Error("Failed to parse address", "error", err.Error(), "addr", string(addr))
				return err
			}
			addrs = append(addrs, ma)
		}
		return nil
	})
	if err != nil {
		if !errors.Is(err, badger.ErrKeyNotFound) {
			st.log.Error("Failed to get addresses from database", "error", err.Error())
		}
	}
	st.log.Debug("Got addresses for peer", "peer", p.String(), "addrs", addrs)
	// If we have a certified record, we'll filter this list to only include
	// addresses that are certified.
	if record, ok := st.peerRecords[p]; ok {
		// If we have a record, we'll filter the addresses.
		if record.Record != nil {
			if record.Expires.Before(time.Now()) {
				// The record has expired, so we'll remove it.
				st.log.Debug("Removing expired record", "peer", p.String())
				delete(st.peerRecords, p)
				return addrs
			}
			st.log.Debug("Filtering addrs by certified record", "peer", p.String(), "addrs", addrs, "certified", record.Record.Addrs)
			var filtered []ma.Multiaddr
			for _, addr := range addrs {
				for _, cert := range record.Record.Addrs {
					if addr.Equal(cert) {
						filtered = append(filtered, addr)
					}
				}
			}
			addrs = filtered
		}
	}
	return addrs
}

// AddrStream returns a channel that gets all addresses for a given
// peer sent on it. If new addresses are added after the call is made
// they will be sent along through the channel as well.
func (st *Peerstore) AddrStream(ctx context.Context, p peer.ID) <-chan ma.Multiaddr {
	ch := make(chan ma.Multiaddr, 100)
	go func() {
		defer close(ch)
		match := []pb.Match{{Prefix: Multiaddrs.PathFor(p).Key()}}
		st.log.Debug("Starting subscription for prefix", "prefix", string(Multiaddrs.PathFor(p).Key()))
		err := st.db.Subscribe(ctx, func(kvs *pb.KVList) error {
			for _, kv := range kvs.Kv {
				addrStr := string(Multiaddrs.PathFor(p).Trim(kv.Key))
				addr, err := ma.NewMultiaddr(addrStr)
				if err != nil {
					st.log.Error("Failed to parse address", "error", err.Error(), "addr", addrStr)
					return err
				}
				st.log.Debug("Got address", "peer", p.String(), "addr", addr.String())
				select {
				case ch <- addr:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return nil
		}, match)
		if err != nil && err != context.Canceled {
			st.log.Error("Failed to subscribe to database", "error", err.Error())
		}
	}()
	return ch
}

// ClearAddresses removes all previously stored addresses.
func (st *Peerstore) ClearAddrs(p peer.ID) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.log.Debug("Clearing addresses for peer", "peer", p.String())
	err := st.db.DropPrefix(Multiaddrs.PathFor(p).Key())
	if err != nil {
		if !errors.Is(err, badger.ErrKeyNotFound) {
			st.log.Error("Failed to drop addresses from database", "error", err.Error())
		}
	}
	delete(st.peerRecords, p)
}

// PeersWithAddrs returns all the peer IDs stored in the AddrBook.
func (st *Peerstore) PeersWithAddrs() peer.IDSlice {
	st.mu.RLock()
	defer st.mu.RUnlock()
	var out peer.IDSlice
	for peer := range st.peerRecords {
		out = util.UpsertSlice(out, peer)
	}
	allPeers := st.Peers()
	err := st.db.View(func(txn *badger.Txn) error {
		for _, peer := range allPeers {
			prefix := Multiaddrs.PathFor(peer)
			opts := badger.DefaultIteratorOptions
			opts.Prefix = prefix.Key()
			opts.PrefetchValues = false
			it := txn.NewIterator(opts)
			for it.Rewind(); it.Valid(); it.Next() {
				// Check that this is a valid multiaddr, and if so, add it to the list.
				addr := prefix.Trim(it.Item().Key())
				_, err := ma.NewMultiaddr(string(addr))
				if err != nil {
					st.log.Error("Failed to parse address", "error", err.Error(), "addr", string(addr))
					continue
				}
				out = util.UpsertSlice(out, peer)
			}
			it.Close()
		}
		return nil
	})
	if err != nil {
		if !errors.Is(err, badger.ErrKeyNotFound) {
			st.log.Error("Failed to iterate over database", "error", err.Error())
		}
	}
	st.log.Debug("Peers with addresses", "peers", out)
	return out
}

// PubKey returns the public key of a peer.
func (st *Peerstore) PubKey(p peer.ID) p2pcrypto.PubKey {
	st.mu.RLock()
	defer st.mu.RUnlock()
	st.log.Debug("Getting public key for peer", "peer", p.String())
	var keyData Key
	err := st.db.View(func(txn *badger.Txn) error {
		key := PublicKeys.PathFor(p).Key()
		item, err := txn.Get(key)
		if err != nil {
			return err
		}
		data, err := item.ValueCopy(nil)
		if err != nil {
			return err
		}
		err = json.Unmarshal(data, &keyData)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		if !errors.Is(err, badger.ErrKeyNotFound) {
			st.log.Error("Failed to get public key from database", "error", err.Error())
			return nil
		}
		st.log.Warn("Lookup for public key not in database", "peer", p.String())
		return nil
	}
	switch keyData.Type {
	case crypto.WireGuardKeyType:
		st.log.Debug("Public key is a wireguard key")
		decoded, err := crypto.DecodePublicKey(keyData.Encoded)
		if err != nil {
			st.log.Error("Failed to decode public key", "error", err.Error())
			return nil
		}
		return decoded
	default:
		st.log.Debug("Public key is a libp2p key")
		decoded, err := p2pcrypto.ConfigDecodeKey(keyData.Encoded)
		if err != nil {
			st.log.Error("Failed to decode public key", "error", err.Error())
			return nil
		}
		key, err := p2pcrypto.UnmarshalPublicKey(decoded)
		if err != nil {
			st.log.Error("Failed to unmarshal public key", "error", err.Error())
			return nil
		}
		return key
	}
}

// AddPubKey stores the public key of a peer.
func (st *Peerstore) AddPubKey(p peer.ID, pubkey p2pcrypto.PubKey) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.log.Debug("Adding public key for peer", "peer", p.String(), "key", pubkey.Type().String())
	var keyData Key
	keyData.Type = pubkey.Type()
	// If this is a wireguard key, we'll use it's encode method.
	if key, ok := pubkey.(crypto.PublicKey); ok {
		st.log.Debug("Public key is a wireguard key")
		encoded, err := key.Encode()
		if err != nil {
			return err
		}
		keyData.Encoded = encoded
	} else {
		// Otherwise, we'll use the p2pcrypto method.
		st.log.Debug("Public key is a libp2p key")
		data, err := p2pcrypto.MarshalPublicKey(pubkey)
		if err != nil {
			return err
		}
		keyData.Encoded = p2pcrypto.ConfigEncodeKey(data)
	}
	// Store the key.
	data, err := json.Marshal(keyData)
	if err != nil {
		return err
	}
	err = st.db.Update(func(txn *badger.Txn) error {
		key := PublicKeys.PathFor(p).Key()
		err := txn.Set(key, data)
		if err != nil {
			return err
		}
		return nil
	})
	return err
}

// PrivKey returns the private key of a peer, if known. Generally this might only be our own
// private key, see
// https://discuss.libp2p.io/t/what-is-the-purpose-of-having-map-peer-id-privatekey-in-peerstore/74.
func (st *Peerstore) PrivKey(p peer.ID) p2pcrypto.PrivKey {
	st.mu.RLock()
	defer st.mu.RUnlock()
	st.log.Debug("Getting private key for peer", "peer", p.String())
	var keyData Key
	err := st.db.View(func(txn *badger.Txn) error {
		key := PrivateKeys.PathFor(p).Key()
		item, err := txn.Get(key)
		if err != nil {
			return err
		}
		data, err := item.ValueCopy(nil)
		if err != nil {
			return err
		}
		err = json.Unmarshal(data, &keyData)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		if !errors.Is(err, badger.ErrKeyNotFound) {
			st.log.Error("Failed to get private key from database", "error", err.Error())
			return nil
		}
		st.log.Warn("Lookup for private key not in database", "peer", p.String())
		return nil
	}
	switch keyData.Type {
	case crypto.WireGuardKeyType:
		st.log.Debug("Private key is a wireguard key")
		decoded, err := crypto.DecodePrivateKey(keyData.Encoded)
		if err != nil {
			st.log.Error("Failed to decode private key", "error", err.Error())
			return nil
		}
		return decoded
	default:
		st.log.Debug("Private key is a libp2p key")
		decoded, err := p2pcrypto.ConfigDecodeKey(keyData.Encoded)
		if err != nil {
			st.log.Error("Failed to decode private key", "error", err.Error())
			return nil
		}
		key, err := p2pcrypto.UnmarshalPrivateKey(decoded)
		if err != nil {
			st.log.Error("Failed to unmarshal private key", "error", err.Error())
			return nil
		}
		return key
	}
}

// AddPrivKey stores the private key of a peer.
func (st *Peerstore) AddPrivKey(p peer.ID, privkey p2pcrypto.PrivKey) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.log.Debug("Adding private key for peer", "peer", p.String(), "key", privkey.Type().String())
	var keyData Key
	keyData.Type = privkey.Type()
	// If this is a wireguard key, we'll use it's encode method.
	if key, ok := privkey.(crypto.PrivateKey); ok {
		st.log.Debug("Private key is a wireguard key")
		encoded, err := key.Encode()
		if err != nil {
			return err
		}
		keyData.Encoded = encoded
	} else {
		// Otherwise, we'll use the p2pcrypto method.
		st.log.Debug("Private key is a libp2p key")
		data, err := p2pcrypto.MarshalPrivateKey(privkey)
		if err != nil {
			return err
		}
		keyData.Encoded = p2pcrypto.ConfigEncodeKey(data)
	}
	// Store the key.
	data, err := json.Marshal(keyData)
	if err != nil {
		return err
	}
	err = st.db.Update(func(txn *badger.Txn) error {
		key := PrivateKeys.PathFor(p).Key()
		err := txn.Set(key, data)
		if err != nil {
			return err
		}
		return nil
	})
	return err
}

// PeersWithKeys returns all the peer IDs stored in the KeyBook.
func (st *Peerstore) PeersWithKeys() peer.IDSlice {
	st.mu.RLock()
	defer st.mu.RUnlock()
	peers := st.Peers()
	var out peer.IDSlice
	err := st.db.View(func(txn *badger.Txn) error {
		for _, peer := range peers {
			key := PrivateKeys.PathFor(peer).Key()
			_, err := txn.Get(key)
			if err != nil {
				if errors.Is(err, badger.ErrKeyNotFound) {
					continue
				}
				return err
			}
			out = util.UpsertSlice(out, peer)
		}
		return nil
	})
	if err != nil {
		if !errors.Is(err, badger.ErrKeyNotFound) {
			st.log.Error("Failed to iterate over database for private keys", "error", err.Error())
		}
	}
	st.log.Debug("Peers with private keys", "peers", out)
	// The same for public
	err = st.db.View(func(txn *badger.Txn) error {
		for _, peer := range peers {
			key := PublicKeys.PathFor(peer).Key()
			_, err := txn.Get(key)
			if err != nil {
				if errors.Is(err, badger.ErrKeyNotFound) {
					continue
				}
				return err
			}
			out = util.UpsertSlice(out, peer)
		}
		return nil
	})
	if err != nil {
		if !errors.Is(err, badger.ErrKeyNotFound) {
			st.log.Error("Failed to iterate over database for public keys", "error", err.Error())
		}
	}
	return out
}

func (st *Peerstore) GetProtocols(p peer.ID) ([]p2pproto.ID, error) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	var out []p2pproto.ID
	err := st.db.View(func(txn *badger.Txn) error {
		prefix := Protocols.PathFor(p)
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		opts.Prefix = prefix.Key()
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			proto := p2pproto.ID(prefix.Trim(it.Item().Key()))
			out = append(out, proto)
		}
		return nil
	})
	if err != nil {
		if !errors.Is(err, badger.ErrKeyNotFound) {
			st.log.Error("Failed to get protocols from database", "error", err.Error())
			return nil, err
		}
	}
	st.log.Debug("Get protocols for peer", "peer", p.String(), "protocols", out)
	return out, nil
}

func (st *Peerstore) AddProtocols(p peer.ID, protos ...p2pproto.ID) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.log.Debug("Add protocols for peer", "peer", p.String(), "protocols", protos)
	prefix := Protocols.PathFor(p)
	err := st.db.Update(func(txn *badger.Txn) error {
		for _, proto := range protos {
			key := prefix.KeyFor(string(proto)).Key()
			err := txn.Set(key, []byte{})
			if err != nil {
				return err
			}
		}
		return nil
	})
	return err
}

func (st *Peerstore) SetProtocols(p peer.ID, protos ...p2pproto.ID) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.log.Debug("Set protocols for peer", "peer", p.String(), "protocols", protos)
	// We'll clear any existing protocols and then write the new ones
	prefix := Protocols.PathFor(p)
	err := st.db.DropPrefix(prefix.Key())
	if err != nil {
		return err
	}
	err = st.db.Update(func(txn *badger.Txn) error {
		for _, proto := range protos {
			key := prefix.KeyFor(string(proto)).Key()
			err := txn.Set(key, []byte{})
			if err != nil {
				return err
			}
		}
		return nil
	})
	return err
}

func (st *Peerstore) RemoveProtocols(p peer.ID, protos ...p2pproto.ID) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.log.Debug("Remove protocols for peer", "peer", p.String(), "protocols", protos)
	err := st.db.DropPrefix(Protocols.PathFor(p).Key())
	if err != nil {
		if !errors.Is(err, badger.ErrKeyNotFound) {
			st.log.Error("Failed to drop protocols from database", "error", err.Error())
			return err
		}
	}
	return nil
}

// SupportsProtocols returns the set of protocols the peer supports from among the given protocols.
// If the returned error is not nil, the result is indeterminate.
func (st *Peerstore) SupportsProtocols(p peer.ID, protos ...p2pproto.ID) ([]p2pproto.ID, error) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	st.log.Debug("Checking if peer supports protocols", "peer", p.String(), "protocols", protos)
	var out []p2pproto.ID
	err := st.db.View(func(txn *badger.Txn) error {
		prefix := Protocols.PathFor(p)
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			proto := p2pproto.ID(prefix.Trim(it.Item().Key()))
			for _, p := range protos {
				if proto == p {
					out = util.UpsertSlice(out, proto)
				}
			}
		}
		return nil
	})
	if err != nil {
		if !errors.Is(err, badger.ErrKeyNotFound) {
			st.log.Error("Failed to get protocols from database", "error", err.Error())
			return nil, err
		}
	}
	st.log.Debug("Peer supports protocols", "peer", p.String(), "protocols", out)
	return out, err
}

// FirstSupportedProtocol returns the first protocol that the peer supports among the given protocols.
// If the peer does not support any of the given protocols, this function will return an empty protocol.ID and a nil error.
// If the returned error is not nil, the result is indeterminate.
func (st *Peerstore) FirstSupportedProtocol(p peer.ID, protos ...p2pproto.ID) (p2pproto.ID, error) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	st.log.Debug("Checking for first peer supported protocol", "peer", p.String(), "protocols", protos)
	var chosen int = -1
	err := st.db.View(func(txn *badger.Txn) error {
		prefix := Protocols.PathFor(p)
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix.Key()
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			proto := p2pproto.ID(prefix.Trim(it.Item().Key()))
			for idx, p := range protos {
				if proto == p {
					if chosen == -1 || idx < chosen {
						chosen = idx
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		if !errors.Is(err, badger.ErrKeyNotFound) {
			st.log.Error("Failed to get protocols from database", "error", err.Error())
			return "", err
		}
	}
	if chosen == -1 {
		st.log.Debug("Peer does not support any of the given protocols", "peer", p.String(), "protocols", protos)
		return "", nil
	}
	return protos[chosen], nil
}

// Get / Put is a simple registry for other peer-related key/value pairs.
// If we find something we use often, it should become its own set of
// methods. This is a last resort.
func (st *Peerstore) Get(p peer.ID, key string) (interface{}, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.log.Debug("Getting peer metadata", "peer", p.String(), "key", key)
	if _, ok := st.peermeta[p]; !ok {
		st.peermeta[p] = make(map[string]any)
	}
	if val, ok := st.peermeta[p][key]; ok {
		return val, nil
	}
	return nil, errors.New("not found")
}

func (st *Peerstore) Put(p peer.ID, key string, val interface{}) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.log.Debug("Putting peer metadata", "peer", p.String(), "key", key, "value", val)
	if _, ok := st.peermeta[p]; !ok {
		st.peermeta[p] = make(map[string]any)
	}
	st.peermeta[p][key] = val
	return nil
}

// RecordLatency records a new latency measurement
func (st *Peerstore) RecordLatency(p peer.ID, dur time.Duration) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.log.Debug("Recording latency observation", "peer", p.String(), "latency", dur.String())
	observation := Observation{
		Time:    time.Now(),
		Latency: dur.String(),
	}
	data, err := json.Marshal(observation)
	if err != nil {
		st.log.Error("Failed to marshal observation", "error", err.Error())
		return
	}
	err = st.db.Update(func(txn *badger.Txn) error {
		key := Observations.PathFor(p).KeyFor(observation.Time.String()).Key()
		err := txn.Set(key, data)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		st.log.Error("Failed to put observation in database", "error", err.Error())
	}
}

// LatencyEWMA returns an exponentially-weighted moving avg.
// of all measurements of a peer's latency.
func (st *Peerstore) LatencyEWMA(p peer.ID) time.Duration {
	st.mu.RLock()
	defer st.mu.RUnlock()
	st.log.Debug("Getting latency EWMA for peer", "peer", p.String())
	var sum time.Duration
	var count int
	err := st.db.View(func(txn *badger.Txn) error {
		prefix := Observations.PathFor(p).Key()
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = true
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			entry := it.Item()
			val, err := entry.ValueCopy(nil)
			if err != nil {
				st.log.Error("Failed to copy value", "error", err.Error())
				continue
			}
			var observation Observation
			err = json.Unmarshal(val, &observation)
			if err != nil {
				st.log.Error("Failed to unmarshal observation", "error", err.Error())
				continue
			}
			dur, err := time.ParseDuration(observation.Latency)
			if err != nil {
				st.log.Error("Failed to parse duration", "error", err.Error())
				continue
			}
			sum += dur
			count++
		}
		return nil
	})
	if err != nil {
		if !errors.Is(err, badger.ErrKeyNotFound) {
			st.log.Error("Failed to iterate over database", "error", err.Error())
		}
		return 0
	}
	if count == 0 {
		return 0
	}
	avg := sum / time.Duration(count)
	st.log.Debug("Got latency EWMA for peer", "peer", p.String(), "ewma", avg.String())
	return avg
}

func (st *Peerstore) ConsumePeerRecord(s *record.Envelope, ttl time.Duration) (accepted bool, err error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	r, err := s.Record()
	if err != nil {
		return false, err
	}
	rec, ok := r.(*peer.PeerRecord)
	if !ok {
		return false, fmt.Errorf("unable to process envelope: not a PeerRecord")
	}
	st.log.Debug("Consuming peer record", "peer", rec.PeerID, "seq", rec.Seq)
	switch v := s.PublicKey.(type) {
	case crypto.WireGuardPublicKey:
		st.log.Debug("Peer record signed by wireguard key")
		matches, err := crypto.IDMatchesPublicKey(rec.PeerID, v)
		if err != nil {
			return false, err
		}
		if !matches {
			return false, fmt.Errorf("signing key does not match PeerID in PeerRecord")
		}
	case p2pcrypto.PubKey:
		st.log.Debug("Peer record signed by libp2p key")
		if !rec.PeerID.MatchesPublicKey(v) {
			return false, fmt.Errorf("signing key does not match PeerID in PeerRecord")
		}
	}

	// Check if we have a record and ensure new seq is higher or equal to.
	if existing, ok := st.peerRecords[rec.PeerID]; ok && existing.Expires.After(time.Now()) {
		if existing.Seq > rec.Seq {
			st.log.Debug("Rejecting peer record",
				"peer", rec.PeerID,
				"seq", rec.Seq,
				"reason", fmt.Sprintf("existing record has higher seq: %d", existing.Seq),
			)
			return false, nil
		}
	}
	// Replace the existing record
	st.log.Debug("Accepting peer record", "peer", rec.PeerID, "seq", rec.Seq, "addrs", rec.Addrs)
	st.peerRecords[rec.PeerID] = PeerRecord{
		Envelope: s,
		Record:   rec,
		Seq:      rec.Seq,
		Expires:  time.Now().Add(ttl),
	}
	return true, nil
}

func (st *Peerstore) GetPeerRecord(p peer.ID) *record.Envelope {
	st.mu.RLock()
	defer st.mu.RUnlock()
	st.log.Debug("Getting peer record", "peer", p.String())
	if rec, ok := st.peerRecords[p]; ok {
		if rec.Expires.Before(time.Now()) {
			// The record has expired
			st.log.Debug("Peer record has expired", "peer", p.String())
			delete(st.peerRecords, p)
			return nil
		}
		return rec.Envelope
	}
	st.log.Debug("No peer record found", "peer", p.String())
	return nil
}
