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
	record "github.com/libp2p/go-libp2p-record"
	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/net/transport"
	"github.com/webmeshproj/webmesh/pkg/util/crypto"
)

// BootstrapOptions are options for the bootstrap transport.
type BootstrapOptions struct {
	// Rendezvous is the rendezvous string to use for the transport.
	// This should be the same for all sides of the transport.
	Rendezvous string
	// PSK a pre-shared key used to sign the results of the election.
	// This should be the same for all sides of the transport.
	PSK crypto.PSK
	// Host are options for configuring a host if one is not provided.
	Host HostOptions
	// ElectionTimeout is the election timeout. The election timeout should
	// be larger than the host's connection timeout. Otherwise, chances
	// of a successful election are low. This does not apply when all sides
	// provide an already bootstrapped host to the transport. All sides of
	// the transport should use the same election timeout.
	ElectionTimeout time.Duration
	// Linger is the time to wait for latecomers to join before closing the host.
	Linger time.Duration
}

// NewBootstrapTransport creates a new bootstrap transport. The host is closed
// when leader election is complete.
func NewBootstrapTransport(ctx context.Context, announcer Announcer, opts BootstrapOptions) (transport.BootstrapTransport, error) {
	host, err := NewHost(ctx, opts.Host)
	if err != nil {
		return nil, err
	}
	return newBootstrapTransportWithClose(host, announcer, opts, func() {
		err := host.Close(ctx)
		if err != nil {
			context.LoggerFrom(ctx).Error("Failed to close host", "error", err.Error())
		}
	}), nil
}

// NewBootstrapTransportWithHost creates a new bootstrap transport with a host.
// The host will remain open after leader election is complete.
func NewBootstrapTransportWithHost(host Host, announcer Announcer, opts BootstrapOptions) transport.BootstrapTransport {
	return newBootstrapTransportWithClose(host, announcer, opts, func() {})
}

func newBootstrapTransportWithClose(host Host, announcer Announcer, opts BootstrapOptions, close func()) transport.BootstrapTransport {
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
	resultKey := fmt.Sprintf("%x", sha256.Sum256([]byte(b.opts.Rendezvous)))
	signer := electionSigner{psk: b.opts.PSK}
	b.host.DHT().Validator = newElectionValidator(signer.verify, b.opts.Rendezvous, resultKey)
	hashResult := func(value []byte) string {
		return fmt.Sprintf("%x", sha256.Sum256(value))
	}

	// Generate and sign a uuid to write to the DHT, largest uuid wins
	ourUUID, err := uuid.NewRandom()
	if err != nil {
		defer b.close()
		return false, nil, fmt.Errorf("failed to generate join PSK: %w", err)
	}
	log := context.LoggerFrom(ctx).With("local-id", b.host.ID().String())
	vote, err := signer.sign(ourUUID[:])
	if err != nil {
		defer b.close()
		return false, nil, fmt.Errorf("failed to sign our UUID: %w", err)
	}

	var leaderUUID uuid.UUID = ourUUID
	var voterCount int

	// Do leader election
	electionDone := time.After(b.opts.ElectionTimeout)
	log.Debug("Writing our UUID to the rendezvous", "rendezvous", b.opts.Rendezvous, "value", ourUUID.String())
	err = b.host.DHT().PutValue(ctx, b.opts.Rendezvous, vote)
	if err != nil {
		defer b.close()
		return false, nil, fmt.Errorf("failed to put our UUID to DHT: %w", err)
	}
	log.Debug("Searching for other values")
	electionValues, err := b.host.DHT().SearchValue(ctx, b.opts.Rendezvous)
	if err != nil {
		defer b.close()
		return false, nil, fmt.Errorf("failed to search DHT for host IDs: %w", err)
	}
	electionResults, err := b.host.DHT().SearchValue(ctx, resultKey)
	if err != nil {
		defer b.close()
		return false, nil, fmt.Errorf("failed to search DHT for election results: %w", err)
	}

LeaderElect:
	for {
		select {
		case <-ctx.Done():
			return false, nil, ctx.Err()
		case <-electionDone:
			log.Debug("Election timeout", "leader", leaderUUID, "voters", voterCount)
			break LeaderElect
		case result := <-electionResults:
			// Verify the signature of the value
			_, err := signer.verify(result)
			if err != nil {
				log.Error("Invalid election result", "error", err.Error())
				// This is not a valid election result. Someone might be playing games.
				// Ignore them.
				continue
			}
			// This is a valid election result. Use it.
			defer b.close()
			rt = NewJoinRoundTripperWithHost(b.host, RoundTripOptions{
				Rendezvous: hashResult(result),
				Method:     v1.Membership_Join_FullMethodName,
			})
			return false, rt, transport.ErrAlreadyBootstrapped
		case vote := <-electionValues:
			if vote == nil {
				continue
			}
			remoteUUID, err := signer.verify(vote)
			if err != nil {
				log.Error("Invalid election vote", "error", err.Error())
				// This is not a valid election vote. Someone might be playing games.
				// Ignore them.
				continue
			}
			if err != nil {
				log.Error("Invalid election vote", "error", err.Error())
				continue
			}
			if err != nil {
				log.Error("Failed to unmarshal UUID from DHT", "error", err.Error())
				continue
			}
			log.Debug("Found another host id", "remote-id", remoteUUID.String())
			if remoteUUID.String() == leaderUUID.String() {
				continue
			}
			if remoteUUID.String() > leaderUUID.String() {
				log.Debug("Found a new leader", "remote-id", remoteUUID.String())
				leaderUUID = remoteUUID
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

	// The winner signs their UUID and writes it to the DHT at a deterministic
	// hash of the initial rendezvous string. This is the string that the others
	// will use to join the cluster. Others performing leader election will
	// see this value and assume the cluster was "already bootstrapped" and
	// receive a transport to the leader. The key's value is signed by a
	// pre-shared key that is known to all nodes in the cluster.
	joinPSK, err := signer.sign(leaderUUID[:])
	if err != nil {
		defer b.close()
		return false, nil, fmt.Errorf("failed to sign leader UUID: %w", err)
	}

	// If we were elected leader, we write the join PSK to the DHT and start
	// an announcer for the others to join.
	if isLeader || voterCount == 0 {
		// Write the signed rendezvous string to the DHT at the result key
		log.Debug("Writing join PSK to the DHT", "key", resultKey, "value", hashResult(joinPSK))
		err = b.host.DHT().PutValue(ctx, resultKey, joinPSK)
		if err != nil {
			defer b.close()
			return false, nil, fmt.Errorf("failed to put join PSK to DHT: %w", err)
		}
		// Start an announcer for the others to join
		err = b.announcer.AnnounceToDHT(ctx, AnnounceOptions{
			Rendezvous:  hashResult(joinPSK),
			AnnounceTTL: time.Minute,
			Method:      v1.Membership_Join_FullMethodName,
			Host:        b.host,
		})
		if err != nil {
			defer b.close()
			return false, nil, fmt.Errorf("failed to start announcer: %w", err)
		}
		if b.opts.Linger > 0 {
			go func() {
				defer b.close()
				<-time.After(b.opts.Linger)
				if err := b.announcer.LeaveDHT(ctx, hashResult(joinPSK)); err != nil {
					log.Error("Failed to close host", "error", err.Error())
				}
			}()
			return
		}
		b.close()
		return
	}
	// Create a transport to the leader with the signed rendezvous string.
	rt = NewJoinRoundTripperWithHost(b.host, RoundTripOptions{
		Rendezvous: hashResult(joinPSK),
		Method:     v1.Membership_Join_FullMethodName,
	})
	b.close()
	return
}

const uuidSize = len(uuid.UUID{})

type electionSigner struct {
	psk crypto.PSK
}

func (s *electionSigner) sign(value []byte) ([]byte, error) {
	sig, err := s.psk.Sign(value)
	if err != nil {
		return nil, err
	}
	return append(value, sig...), nil
}

func (s *electionSigner) verify(value []byte) (uuid.UUID, error) {
	sigSize := s.psk.SignatureSize()
	if len(value) < uuidSize+sigSize {
		return uuid.UUID{}, fmt.Errorf("invalid value length")
	}
	remoteUUID := value[:len(value)-sigSize]
	sig := value[len(value)-sigSize:]
	err := s.psk.Verify(remoteUUID, sig)
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("invalid signature: %w", err)
	}
	var uu uuid.UUID
	copy(uu[:], remoteUUID)
	return uu, nil
}

type electionValidator struct {
	electionKey string
	resultsKey  string
	verify      func([]byte) (uuid.UUID, error)
}

func newElectionValidator(verify func([]byte) (uuid.UUID, error), electionKey, resultsKey string) record.Validator {
	return &electionValidator{
		electionKey: electionKey,
		resultsKey:  resultsKey,
		verify:      verify,
	}
}

// Validate validates the given record, returning an error if it's
// invalid (e.g., expired, signed by the wrong key, etc.).
func (e *electionValidator) Validate(key string, value []byte) error {
	_, err := e.verify(value)
	if err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}
	return nil
}

// Select selects the best record from the set of records (e.g., the
// newest).
//
// Decisions made by select should be stable.
func (e *electionValidator) Select(key string, values [][]byte) (int, error) {
	// Validate each value and return the largest
	var largest int
	for i, val := range values {
		if err := e.Validate(key, val); err != nil {
			return 0, err
		}
		if string(val) > string(values[largest]) {
			largest = i
		}
	}
	return largest, nil
}
