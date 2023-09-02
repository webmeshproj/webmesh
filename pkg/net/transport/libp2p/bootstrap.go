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

package libp2p

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/google/uuid"
	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/net/transport"
	"github.com/webmeshproj/webmesh/pkg/util/crypto"
)

// BootstrapOptions are options for the bootstrap transport.
type BootstrapOptions struct {
	// Rendezvous is the rendezvous string to use for the transport.
	Rendezvous string
	// PSK a pre-shared key used to sign the results of the election.
	PSK crypto.PSK
	// Host are options for configuring the host.
	Host HostOptions
	// ElectionTimeout is the election timeout.
	ElectionTimeout time.Duration
	// Linger is the time to wait for non-leaders to join before closing the host.
	Linger time.Duration
}

// NewBootstrapTransport creates a new bootstrap transport.
func NewBootstrapTransport(ctx context.Context, opts BootstrapOptions, announcer Announcer) (transport.BootstrapTransport, error) {
	host, err := NewHost(ctx, opts.Host)
	if err != nil {
		return nil, err
	}
	return newBootstrapTransportWithClose(opts, host, announcer, func() {
		err := host.Close(ctx)
		if err != nil {
			context.LoggerFrom(ctx).Error("Failed to close host", "error", err.Error())
		}
	}), nil
}

// NewBootstrapTransportWithHost creates a new bootstrap transport with a host.
func NewBootstrapTransportWithHost(opts BootstrapOptions, host Host, announcer Announcer) transport.BootstrapTransport {
	return newBootstrapTransportWithClose(opts, host, announcer, func() {})
}

func newBootstrapTransportWithClose(opts BootstrapOptions, host Host, announcer Announcer, close func()) transport.BootstrapTransport {
	return &bootstrapTransport{
		opts:      opts,
		host:      host,
		announcer: announcer,
		close:     close,
	}
}

type bootstrapTransport struct {
	opts      BootstrapOptions
	host      Host
	announcer Announcer
	close     func()
}

func (b *bootstrapTransport) LeaderElect(ctx context.Context) (isLeader bool, rt transport.JoinRoundTripper, err error) {
	done := time.After(b.opts.ElectionTimeout)
	results := sha256.New()
	results.Write([]byte(b.opts.Rendezvous))
	resultKey := fmt.Sprintf("%x", results.Sum(nil))

	// Generate a uuid to write to the DHT, largest uuid wins
	joinUUID, err := uuid.NewRandom()
	if err != nil {
		return false, nil, fmt.Errorf("failed to generate join PSK: %w", err)
	}
	log := context.LoggerFrom(ctx).With("local-id", b.host.ID().String())
	ourUUID := joinUUID
	var leaderUUID = joinUUID
	var voterCount int
	// Do leader election
	log.Debug("Writing our host ID to the rendezvous", "rendezvous", b.opts.Rendezvous)
	data, err := ourUUID.MarshalBinary()
	if err != nil {
		return false, nil, fmt.Errorf("failed to marshal UUID: %w", err)
	}
	err = b.host.DHT().PutValue(ctx, b.opts.Rendezvous, data)
	if err != nil {
		return false, nil, fmt.Errorf("failed to put host ID to DHT: %w", err)
	}
	log.Debug("Searching for other values")
	electionValues, err := b.host.DHT().SearchValue(ctx, b.opts.Rendezvous)
	if err != nil {
		return false, nil, fmt.Errorf("failed to search DHT for host IDs: %w", err)
	}
	electionResults, err := b.host.DHT().SearchValue(ctx, resultKey)
	if err != nil {
		return false, nil, fmt.Errorf("failed to search DHT for election results: %w", err)
	}

LeaderElect:
	for {
		select {
		case <-ctx.Done():
			return false, nil, ctx.Err()
		case <-done:
			log.Debug("Election timeout", "leader", leaderUUID, "voters", voterCount)
			break LeaderElect
		case val := <-electionResults:
			// Verify the signature of the value
			if len(val) <= len(ourUUID) {
				log.Error("Invalid election result", "error", "invalid length")
				continue
			}
			sig := val[len(ourUUID):]
			joinPSK := val[:len(ourUUID)]
			err := b.opts.PSK.Verify(joinPSK, sig)
			if err != nil {
				log.Error("Invalid election result", "error", err.Error())
				continue
			}
			// This is a valid election result. Use it.
			joinRendezvous := fmt.Sprintf("%x", sha256.Sum256(joinPSK))
			err = transport.ErrAlreadyBootstrapped
			rt = NewJoinRoundTripperWithHost(b.host, RoundTripOptions{
				Rendezvous: joinRendezvous,
				Method:     v1.Membership_Join_FullMethodName,
			})
			return false, rt, err
		case val := <-electionValues:
			if val == nil {
				continue
			}
			var uu uuid.UUID
			err := uu.UnmarshalBinary(val)
			if err != nil {
				log.Error("Failed to unmarshal UUID from DHT", "error", err.Error())
				continue
			}
			log.Debug("Found another host id", "remote-id", string(val))
			if string(val) > leaderUUID.String() {
				log.Debug("Found a new leader", "remote-id", string(val))
				leaderUUID = uu
			} else if uu.String() == ourUUID.String() {
				// Skip our own value
				continue
			}
			voterCount++
			continue
		}
	}
	if voterCount == 0 {
		log.Warn("No other voters found within the election period")
	}
	if leaderUUID.String() == ourUUID.String() {
		// Start an announcer for the others to join
		log.Debug("We are the leader", "voters", voterCount)
		isLeader = true
	} else {
		log.Debug("We were not elected leader", "leader", leaderUUID.String(), "voters", voterCount)
	}

	// The winner generates a string and writes it to the DHT at a deterministic
	// hash of the initial rendezvous string. This is the string that the others
	// will use to join the cluster. Others performing leader election will
	// see this value and assume the cluster was "already bootstrapped" and
	// receive a transport to the leader. The key's value is signed by a
	// pre-shared key that is known to all nodes in the cluster.
	sig, err := b.opts.PSK.Sign(leaderUUID[:])
	if err != nil {
		return false, nil, fmt.Errorf("failed to sign leader UUID: %w", err)
	}
	joinPSK := append(leaderUUID[:], sig...)
	joinRendezvous := fmt.Sprintf("%x", sha256.Sum256(joinPSK))

	// If we were elected leader, we write the join PSK to the DHT and start
	// an announcer for the others to join.
	if isLeader || voterCount == 0 {
		// Write the signed rendezvous string to the DHT at the result key
		log.Debug("Writing join PSK to the DHT", "key", resultKey, "value", joinRendezvous)
		err = b.host.DHT().PutValue(ctx, resultKey, joinPSK)
		if err != nil {
			return false, nil, fmt.Errorf("failed to put join PSK to DHT: %w", err)
		}
		// Start an announcer for the others to join
		err = b.announcer.AnnounceToDHT(ctx, AnnounceOptions{
			Rendezvous:  joinRendezvous,
			AnnounceTTL: time.Minute,
			Method:      v1.Membership_Join_FullMethodName,
			Host:        b.host,
		})
		return
	}

	// Create a transport to the leader with the signed rendezvous string.
	rt = NewJoinRoundTripperWithHost(b.host, RoundTripOptions{
		Rendezvous: joinRendezvous,
		Method:     v1.Membership_Join_FullMethodName,
	})
	go func() {
		defer b.close()
		<-time.After(b.opts.Linger)
		if err := b.announcer.LeaveDHT(ctx, joinRendezvous); err != nil {
			log.Error("Failed to close host", "error", err.Error())
		}
	}()
	return
}
