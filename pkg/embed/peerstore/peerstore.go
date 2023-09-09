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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sync"
	"time"

	p2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	cryptopb "github.com/libp2p/go-libp2p/core/crypto/pb"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	p2pproto "github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/core/record"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/nutsdb/nutsdb/inmemory"

	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/storage/nutsdb"
)

// Ensure we implement the interfaces.
var _ peerstore.Peerstore = (*Peerstore)(nil)
var _ peerstore.CertifiedAddrBook = (*Peerstore)(nil)

// New returns a new peerstore.
func New(log *slog.Logger) *Peerstore {
	db, err := inmemory.Open(inmemory.DefaultOptions)
	if err != nil {
		panic(fmt.Errorf("failed to open in-memory database: %w", err))
	}
	return &Peerstore{
		db:          db,
		protocols:   make(map[peer.ID][]p2pproto.ID),
		peermeta:    make(map[peer.ID]map[string]any),
		peerRecords: make(map[peer.ID]PeerRecord),
		log:         log,
	}
}

// Peerstore is a libp2p peerstore.
type Peerstore struct {
	db          *inmemory.DB
	addrPeers   peerIDSlice
	keyPeers    peerIDSlice
	protocols   map[peer.ID][]p2pproto.ID
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
}

// Prefix is a prefix for values in the database.
type Prefix string

const (
	PrivateKeyKey      Prefix = "/private-key"
	PublicKeyKey       Prefix = "/public-key"
	AddrPrefix         Prefix = "/addrs"
	ObservationsPrefix Prefix = "/observations"
)

func (p Prefix) Key() []byte { return []byte(p) }

func (p Prefix) String() string { return string(p) }

func (p Prefix) KeyFor(value string) []byte {
	return append([]byte(p), []byte(value)...)
}

func (p Prefix) TrimPrefix(key []byte) []byte {
	return key[len(p):]
}

// Close closes the peerstore. This is a no-op.
func (st *Peerstore) Close() error {
	return nil
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
	return st.addrPeers.Merge(st.keyPeers).Copy()
}

// RemovePeer removes all data associated with a peer.
func (st *Peerstore) RemovePeer(p peer.ID) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.log.Debug("Removing peer", "peer", p.String())
	st.addrPeers = st.addrPeers.Remove(p)
	st.keyPeers = st.keyPeers.Remove(p)
	delete(st.protocols, p)
	delete(st.peermeta, p)
	delete(st.peerRecords, p)
	// Delete everything in the bucket for this peer.
	entries, _, err := st.db.PrefixScan(p.String(), []byte{}, 0, math.MaxInt)
	if err != nil {
		if !nutsdb.IsNotFound(err) {
			st.log.Error("Failed to get peer from database", "error", err.Error())
		}
		return
	}
	for _, entry := range entries {
		err := st.db.Delete(p.String(), entry.Key)
		if err != nil {
			st.log.Error("Failed to delete peer from database", "error", err.Error())
		}
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
	for _, addr := range addrs {
		err := st.db.Put(p.String(), AddrPrefix.KeyFor(addr.String()), []byte{}, uint32(ttl.Seconds()))
		if err != nil {
			st.log.Error("Failed to put address in database", "error", err.Error())
		}
	}
	// Check if the peer is already in the list.
	st.addrPeers = st.addrPeers.Upsert(p)
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
	for _, addr := range addrs {
		err := st.db.Put(p.String(), AddrPrefix.KeyFor(addr.String()), []byte{}, uint32(ttl.Seconds()))
		if err != nil {
			st.log.Error("Failed to put address in database", "error", err.Error())
		}
	}
	st.addrPeers = st.addrPeers.Upsert(p)
}

// UpdateAddrs updates the addresses associated with the given peer that have
// the given oldTTL to have the given newTTL.
func (st *Peerstore) UpdateAddrs(p peer.ID, oldTTL time.Duration, newTTL time.Duration) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.log.Debug("Updating addresses for peer", "peer", p.String(), "oldTTL", oldTTL, "newTTL", newTTL)
	entries, _, err := st.db.PrefixScan(p.String(), []byte(AddrPrefix), 0, math.MaxInt)
	if err != nil {
		if !nutsdb.IsNotFound(err) {
			st.log.Error("Failed to get addresses from database", "error", err.Error())
		}
		return
	}
	for _, entry := range entries {
		if entry.Meta.TTL == 0 {
			continue
		}
		if !ttlInRange(entry.Meta.TTL, oldTTL-time.Second, oldTTL+time.Second) {
			continue
		}
		st.log.Debug("Updating address", "peer", p.String(),
			"addr", string(AddrPrefix.TrimPrefix(entry.Key)),
			"oldTTL", oldTTL,
			"newTTL", newTTL,
		)
		err := st.db.Put(p.String(), AddrPrefix.KeyFor(string(entry.Key)), []byte{}, uint32(newTTL.Seconds()))
		if err != nil {
			st.log.Error("Failed to put address in database", "error", err.Error())
		}
	}
	st.addrPeers = st.addrPeers.Upsert(p)
}

func ttlInRange(ttl uint32, min time.Duration, max time.Duration) bool {
	ttlDur := time.Duration(ttl) * time.Second
	return ttlDur >= min && ttlDur <= max
}

// Addrs returns all known (and valid) addresses for a given peer.
func (st *Peerstore) Addrs(p peer.ID) []ma.Multiaddr {
	st.mu.RLock()
	defer st.mu.RUnlock()
	st.log.Debug("Getting addresses for peer", "peer", p.String())
	entries, _, err := st.db.PrefixScan(p.String(), []byte(AddrPrefix), 0, math.MaxInt)
	if err != nil {
		if !nutsdb.IsNotFound(err) {
			st.log.Error("Failed to get addresses from database", "error", err.Error())
		}
		return nil
	}
	var out []ma.Multiaddr
	for _, entry := range entries {
		addr, err := ma.NewMultiaddr(string(AddrPrefix.TrimPrefix(entry.Key)))
		if err != nil {
			st.log.Error("Failed to get address from database", "error", err.Error())
			continue
		}
		out = append(out, addr)
	}
	st.log.Debug("Got addresses for peer", "peer", p.String(), "addrs", out)
	// If we have a certified record, we'll filter this list to only include
	// addresses that are certified.
	if record, ok := st.peerRecords[p]; ok {
		// If we have a record, we'll filter the addresses.
		if record.Record != nil {
			st.log.Debug("Filtering addrs by certified record", "peer", p.String(), "addrs", out, "certified", record.Record.Addrs)
			var filtered []ma.Multiaddr
			for _, addr := range out {
				for _, cert := range record.Record.Addrs {
					if addr.Equal(cert) {
						filtered = append(filtered, addr)
					}
				}
			}
			out = filtered
		}
	}
	return out
}

// AddrStream returns a channel that gets all addresses for a given
// peer sent on it. If new addresses are added after the call is made
// they will be sent along through the channel as well.
func (st *Peerstore) AddrStream(ctx context.Context, p peer.ID) <-chan ma.Multiaddr {
	ch := make(chan ma.Multiaddr, 1)
	go func() {
		defer close(ch)
		sent := make(map[string]struct{})
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(1 * time.Second):
				addrs := st.Addrs(p)
				for _, addr := range addrs {
					if _, ok := sent[addr.String()]; ok {
						continue
					}
					sent[addr.String()] = struct{}{}
					select {
					case <-ctx.Done():
						return
					case ch <- addr:
					}
				}
			}
		}
	}()
	return ch
}

// ClearAddresses removes all previously stored addresses.
func (st *Peerstore) ClearAddrs(p peer.ID) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.log.Debug("Clearing addresses for peer", "peer", p.String())
	entries, _, err := st.db.PrefixScan(p.String(), []byte(AddrPrefix), 0, math.MaxInt)
	if err != nil {
		if !nutsdb.IsNotFound(err) {
			st.log.Error("Failed to get addresses from database", "error", err.Error())
		}
		return
	}
	for _, entry := range entries {
		st.log.Debug("Clearing address", "peer", p.String(), "addr", string(AddrPrefix.TrimPrefix(entry.Key)))
		err := st.db.Delete(p.String(), entry.Key)
		if err != nil {
			st.log.Error("Failed to delete address from database", "error", err.Error())
		}
	}
	// Remove the peer from the list.
	st.addrPeers = st.addrPeers.Remove(p)
}

// PeersWithAddrs returns all the peer IDs stored in the AddrBook.
func (st *Peerstore) PeersWithAddrs() peer.IDSlice {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.addrPeers.Copy()
}

// PubKey returns the public key of a peer.
func (st *Peerstore) PubKey(p peer.ID) p2pcrypto.PubKey {
	st.mu.RLock()
	defer st.mu.RUnlock()
	st.log.Debug("Getting public key for peer", "peer", p.String())
	data, err := st.db.Get(p.String(), PublicKeyKey.Key())
	if err != nil {
		if !nutsdb.IsNotFound(err) {
			st.log.Error("Failed to get public key from database", "error", err.Error())
		}
		st.log.Warn("Lookup for public key not in database", "peer", p.String())
		return nil
	}
	var keyData Key
	err = json.Unmarshal(data.Value, &keyData)
	if err != nil {
		st.log.Error("Failed to unmarshal public key from database", "error", err.Error())
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
	err = st.db.Put(p.String(), PublicKeyKey.Key(), data, 0)
	if err != nil {
		return err
	}
	st.keyPeers = st.keyPeers.Upsert(p)
	return nil
}

// PrivKey returns the private key of a peer, if known. Generally this might only be our own
// private key, see
// https://discuss.libp2p.io/t/what-is-the-purpose-of-having-map-peer-id-privatekey-in-peerstore/74.
func (st *Peerstore) PrivKey(p peer.ID) p2pcrypto.PrivKey {
	st.mu.RLock()
	defer st.mu.RUnlock()
	st.log.Debug("Getting private key for peer", "peer", p.String())
	data, err := st.db.Get(p.String(), PrivateKeyKey.Key())
	if err != nil {
		if !nutsdb.IsNotFound(err) {
			st.log.Error("Failed to get private key from database", "error", err.Error())
		}
		st.log.Warn("Lookup for private key not in database", "peer", p.String())
		return nil
	}
	var keyData Key
	err = json.Unmarshal(data.Value, &keyData)
	if err != nil {
		st.log.Error("Failed to unmarshal private key from database", "error", err.Error())
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
	err = st.db.Put(p.String(), PrivateKeyKey.Key(), data, 0)
	if err != nil {
		return err
	}
	st.keyPeers = st.keyPeers.Upsert(p)
	return nil
}

// PeersWithKeys returns all the peer IDs stored in the KeyBook.
func (st *Peerstore) PeersWithKeys() peer.IDSlice {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.keyPeers.Copy()
}

func (st *Peerstore) GetProtocols(p peer.ID) ([]p2pproto.ID, error) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	var out []p2pproto.ID
	if len(st.protocols[p]) > 0 {
		out = append(out, st.protocols[p]...)
	}
	st.log.Debug("Get protocols for peer", "peer", p.String(), "protocols", out)
	return out, nil
}

func (st *Peerstore) AddProtocols(p peer.ID, protos ...p2pproto.ID) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.log.Debug("Add protocols for peer", "peer", p.String(), "protocols", protos)
	st.protocols[p] = append(st.protocols[p], protos...)
	return nil
}

func (st *Peerstore) SetProtocols(p peer.ID, protos ...p2pproto.ID) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.log.Debug("Set protocols for peer", "peer", p.String(), "protocols", protos)
	st.protocols[p] = protos
	return nil
}

func (st *Peerstore) RemoveProtocols(p peer.ID, protos ...p2pproto.ID) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.log.Debug("Remove protocols for peer", "peer", p.String(), "protocols", protos)
	for _, proto := range protos {
		for i, pr := range st.protocols[p] {
			if pr == proto {
				st.protocols[p] = append(st.protocols[p][:i], st.protocols[p][i+1:]...)
			}
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
	if len(st.protocols[p]) > 0 {
		for _, proto := range protos {
			for _, pr := range st.protocols[p] {
				if pr == proto {
					st.log.Debug("Peer supports protocol", "peer", p.String(), "protocol", proto)
					out = append(out, proto)
				}
			}
		}
	}
	st.log.Debug("Peer supports protocols", "peer", p.String(), "protocols", out)
	return out, nil
}

// FirstSupportedProtocol returns the first protocol that the peer supports among the given protocols.
// If the peer does not support any of the given protocols, this function will return an empty protocol.ID and a nil error.
// If the returned error is not nil, the result is indeterminate.
func (st *Peerstore) FirstSupportedProtocol(p peer.ID, protos ...p2pproto.ID) (p2pproto.ID, error) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	st.log.Debug("Checking for first peer supported protocol", "peer", p.String(), "protocols", protos)
	if len(st.protocols[p]) > 0 {
		st.log.Debug("Peer supports protocols", "peer", p.String(), "protocols", st.protocols[p])
		for _, proto := range protos {
			for _, pr := range st.protocols[p] {
				if pr == proto {
					st.log.Debug("Peer supports protocol", "peer", p.String(), "protocol", proto)
					return proto, nil
				}
			}
		}
	}
	return "", nil
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
	err = st.db.Put(p.String(), ObservationsPrefix.KeyFor(observation.Time.String()), data, 0)
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
	entries, _, err := st.db.PrefixScan(p.String(), []byte(ObservationsPrefix), 0, math.MaxInt)
	if err != nil {
		if !nutsdb.IsNotFound(err) {
			st.log.Error("Failed to get observations from database", "error", err.Error())
		}
		st.log.Debug("No observations for peer", "peer", p.String())
		return 0
	}
	if len(entries) == 0 {
		st.log.Debug("No observations for peer", "peer", p.String())
		return 0
	}
	// Calculate the exponential moving average.
	var sum time.Duration
	for _, entry := range entries {
		var observation Observation
		err := json.Unmarshal(entry.Value, &observation)
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
	}
	avg := sum / time.Duration(len(entries))
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
	if !rec.PeerID.MatchesPublicKey(s.PublicKey) {
		return false, fmt.Errorf("signing key does not match PeerID in PeerRecord")
	}
	// Check if we have a record and ensure new seq is higher or equal to.
	if existing, ok := st.peerRecords[rec.PeerID]; ok {
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
	}
	return true, nil
}

func (st *Peerstore) GetPeerRecord(p peer.ID) *record.Envelope {
	st.mu.RLock()
	defer st.mu.RUnlock()
	st.log.Debug("Getting peer record", "peer", p.String())
	if rec, ok := st.peerRecords[p]; ok {
		return rec.Envelope
	}
	st.log.Debug("No peer record found", "peer", p.String())
	return nil
}
