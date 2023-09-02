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
	"sync"
	"time"

	"github.com/google/uuid"
	record "github.com/libp2p/go-libp2p-record"
	"github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/network"
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	dutil "github.com/libp2p/go-libp2p/p2p/discovery/util"
	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/net/transport"
	"github.com/webmeshproj/webmesh/pkg/util/crypto"
)

// BootstrapTransport implements bootstrap transport and returns the
// local UUID that was used for voting.
type BootstrapTransport interface {
	transport.BootstrapTransport

	// UUID returns the local UUID that was used for voting.
	UUID() uuid.UUID
	// LeaderUUID returns the UUID of the leader that was elected.
	// This is only populated after leader election is complete.
	LeaderUUID() uuid.UUID
}

// BootstrapOptions are options for the bootstrap transport.
type BootstrapOptions struct {
	// Rendezvous is the rendezvous string to use for the transport.
	// This should be the same for all sides of the transport.
	Rendezvous string
	// Signer is provided to sign and verify the UUIDs of the voters.
	Signer crypto.Signer
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
func NewBootstrapTransport(ctx context.Context, announcer Announcer, opts BootstrapOptions) (BootstrapTransport, error) {
	uu, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}
	host, err := NewHost(ctx, opts.Host)
	if err != nil {
		return nil, err
	}
	return newBootstrapTransportWithClose(host, announcer, opts, uu, func() {
		err := host.Close(ctx)
		if err != nil {
			context.LoggerFrom(ctx).Error("Failed to close host", "error", err.Error())
		}
	}), nil
}

// NewBootstrapTransportWithHost creates a new bootstrap transport with a host.
// The host will remain open after leader election is complete.
func NewBootstrapTransportWithHost(host Host, announcer Announcer, opts BootstrapOptions) (BootstrapTransport, error) {
	uu, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}
	return newBootstrapTransportWithClose(host, announcer, opts, uu, func() {}), nil
}

func newBootstrapTransportWithClose(host Host, announcer Announcer, opts BootstrapOptions, localUUID uuid.UUID, close func()) BootstrapTransport {
	return &bootstrapTransport{
		opts:      opts,
		host:      host,
		localUUID: localUUID,
		announcer: announcer,
		close:     close,
	}
}

type bootstrapTransport struct {
	opts                  BootstrapOptions
	host                  Host
	localUUID, leaderUUID uuid.UUID
	announcer             Announcer
	close                 func()
}

func (b *bootstrapTransport) UUID() uuid.UUID {
	return b.localUUID
}

func (b *bootstrapTransport) LeaderUUID() uuid.UUID {
	return b.leaderUUID
}

func (b *bootstrapTransport) LeaderElect(ctx context.Context) (isLeader bool, rt transport.JoinRoundTripper, err error) {
	resultKey := fmt.Sprintf("%x", sha256.Sum256([]byte(b.opts.Rendezvous)))
	log := context.LoggerFrom(ctx).With(
		"local-id", b.localUUID,
		"rendezvous", b.opts.Rendezvous,
		"host-id", b.host.ID(),
		"result-key", resultKey,
	)
	signer := electionSigner{signer: b.opts.Signer}
	b.host.DHT().Validator = newElectionValidator(signer.verify, b.opts.Rendezvous, resultKey)
	hashResult := func(value []byte) string {
		return fmt.Sprintf("%x", sha256.Sum256(value))
	}
	routingDiscovery := drouting.NewRoutingDiscovery(b.host.DHT())

	vote, err := signer.sign(b.localUUID[:])
	if err != nil {
		defer b.close()
		return false, nil, fmt.Errorf("failed to sign our UUID: %w", err)
	}
	log = log.With("vote", hashResult(vote))

	log.Debug("Advertising leader election and setting up stream handler")
	acceptc := make(chan network.Stream, 1)
	b.host.Host().SetStreamHandler(BootstrapProtocol, func(s network.Stream) {
		go func() { acceptc <- s }()
	})
	defer b.host.Host().RemoveStreamHandler(BootstrapProtocol)
	advertiseCtx, advertiseCancel := context.WithCancel(ctx)
	dutil.Advertise(advertiseCtx, routingDiscovery, b.opts.Rendezvous, discovery.TTL(b.opts.ElectionTimeout))
	peerc, err := routingDiscovery.FindPeers(ctx, b.opts.Rendezvous)
	if err != nil {
		defer b.close()
		return false, nil, fmt.Errorf("libp2p find peers: %w", err)
	}
	log.Debug("Searching for results from a previous election")
	electionResults, err := b.host.DHT().SearchValue(ctx, resultKey)
	if err != nil {
		defer b.close()
		return false, nil, fmt.Errorf("failed to search DHT for election results: %w", err)
	}

	// Do leader election
	var leaderUUID uuid.UUID = b.localUUID
	var voterCount int
	var votemu sync.Mutex

	log.Debug("Starting leader election")
	electionDone := time.After(b.opts.ElectionTimeout)

LeaderElect:
	for {
		select {
		case <-ctx.Done():
			return false, nil, ctx.Err()
		case <-electionDone:
			log.Debug("Election timeout", "num-voters", voterCount)
			break LeaderElect
		case result := <-electionResults:
			// Verify the signature of the value
			log.Debug("Found a previous election result", "key", resultKey, "value", hashResult(result))
			leader, err := signer.verify(result)
			if err != nil {
				log.Error("Invalid election result", "error", err.Error())
				// This is not a valid election result. Someone might be playing games.
				// Ignore them.
				continue
			}
			// This is a valid election result. Use it.
			b.leaderUUID = leader
			defer advertiseCancel()
			defer b.close()
			rt = NewJoinRoundTripperWithHost(b.host, RoundTripOptions{
				Rendezvous: hashResult(result),
				Method:     v1.Membership_Join_FullMethodName,
			})
			return false, rt, transport.ErrAlreadyBootstrapped
		case voter := <-acceptc:
			go func() {
				votemu.Lock()
				defer votemu.Unlock()
				select {
				case <-electionDone:
					return
				case <-advertiseCtx.Done():
					return
				default:
				}
				log.Debug("Received a vote", "remote-host-id", voter.Conn().RemotePeer().String())
				defer voter.Close()
				buf := make([]byte, len(vote))
				_, err := voter.Read(buf)
				if err != nil {
					log.Error("Failed to read vote", "error", err.Error())
					return
				}
				remoteUUID, err := signer.verify(buf)
				if err != nil {
					log.Error("Invalid election vote", "error", err.Error())
					// This is not a valid election vote. Someone might be playing games.
					// Ignore them.
					return
				}
				log.Debug("Vote is valid", "remote-vote", hashResult(buf))
				if remoteUUID.String() == leaderUUID.String() {
					return
				}
				if remoteUUID.String() > leaderUUID.String() {
					log.Debug("Found a new leader", "remote-vote", hashResult(buf))
					leaderUUID = remoteUUID
				}
				voterCount++
			}()
		case voter := <-peerc:
			if voter.ID == b.host.ID() {
				continue
			}
			go func() {
				log.Debug("Found a voter", "remote-host-id", voter.ID.String())
				connectCtx, cancel := context.WithTimeout(ctx, b.opts.Host.ConnectTimeout)
				defer cancel()
				conn, err := b.host.Host().NewStream(connectCtx, voter.ID, BootstrapProtocol)
				if err != nil {
					log.Error("Failed to create stream", "error", err.Error())
					return
				}
				defer conn.Close()
				log.Debug("Sending vote", "remote-host-id", voter.ID.String())
				_, err = conn.Write(vote)
				if err != nil {
					log.Error("Failed to write vote", "error", err.Error())
				}
			}()
		}
	}

	advertiseCancel()

	if voterCount == 0 {
		log.Warn("No other voters found within the election period")
	}
	if leaderUUID.String() == b.localUUID.String() {
		// Start an announcer for the others to join
		log.Debug("We are the leader", "voters", voterCount)
		isLeader = true
	} else {
		log.Debug("We were not elected leader", "leader", leaderUUID.String(), "voters", voterCount)
	}

	b.leaderUUID = leaderUUID

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
	signer crypto.Signer
}

func (s *electionSigner) sign(value []byte) ([]byte, error) {
	sig, err := s.signer.Sign(value)
	if err != nil {
		return nil, err
	}
	return append(value, sig...), nil
}

func (s *electionSigner) verify(value []byte) (uuid.UUID, error) {
	sigSize := s.signer.SignatureSize()
	if len(value) < uuidSize+sigSize {
		return uuid.UUID{}, fmt.Errorf("invalid value length")
	}
	remoteUUID := value[:len(value)-sigSize]
	sig := value[len(value)-sigSize:]
	err := s.signer.Verify(remoteUUID, sig)
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
