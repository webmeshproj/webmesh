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
	"bufio"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/google/uuid"
	record "github.com/libp2p/go-libp2p-record"
	"github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	dutil "github.com/libp2p/go-libp2p/p2p/discovery/util"
	v1 "github.com/webmeshproj/api/v1"
	"golang.org/x/crypto/sha3"

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
	Signer crypto.PSK
	// Host are options for configuring a host if one is not provided.
	Host HostOptions
	// ElectionTimeout is the election timeout. The election timeout should
	// be larger than the host's connection timeout. Otherwise, chances
	// of a successful election are low. This does not apply when all sides
	// provide an already bootstrapped host to the transport. All sides of
	// the transport should use the same election timeout.
	ElectionTimeout time.Duration
	// Linger is the time to wait for non-leaders to join before closing the host.
	Linger time.Duration
	// NodeID is the node ID to use for leader election. This should be the
	// local node ID.
	NodeID string
	// NodeIDs are the other node IDs to use for leader election.
	NodeIDs []string
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
	privKey := b.host.Host().Peerstore().PrivKey(b.host.Host().ID())
	if err != nil {
		return false, nil, fmt.Errorf("failed to extract public key from host ID: %w", err)
	}
	hash := func(value []byte) string {
		return fmt.Sprintf("%x", sha3.Sum224(value))
	}
	electionContext, electionCancel := context.WithCancel(ctx)
	signer := electionSigner{signer: b.opts.Signer}
	b.host.DHT().Validator = newElectionValidator()
	resultKey := hash([]byte(b.opts.Rendezvous))
	log := context.LoggerFrom(ctx).With(
		"rendezvous", b.opts.Rendezvous,
		"host-id", b.host.ID(),
		"result-key", resultKey,
		"local-uuid", b.localUUID,
	)

	vote, err := signer.sign(b.localUUID)
	if err != nil {
		defer b.close()
		return false, nil, fmt.Errorf("failed to sign our UUID: %w", err)
	}

	log.Debug("Advertising leader election and setting up stream handler")
	acceptc := make(chan network.Stream, 100)
	b.host.Host().SetStreamHandler(BootstrapProtocol, func(s network.Stream) {
		acceptc <- s
	})
	defer b.host.Host().RemoveStreamHandler(BootstrapProtocol)

	advertiseCtx, advertiseCancel := context.WithCancel(context.Background())
	defer advertiseCancel()
	routingDiscovery := drouting.NewRoutingDiscovery(b.host.DHT())
	dutil.Advertise(advertiseCtx, routingDiscovery, b.opts.Rendezvous, discovery.TTL(b.opts.ElectionTimeout))

	seenPeers := make(map[peer.ID]struct{})
	peerc := make(chan peer.AddrInfo, 100)
	go func(rendezvous string) {
		defer close(peerc)
		for {
			select {
			case <-electionContext.Done():
				return
			default:
			}
			log.Debug("Searching for remote voters")
			peers, err := routingDiscovery.FindPeers(context.Background(), rendezvous)
			if err != nil {
				log.Warn("Failed to find peers", "error", err.Error())
				return
			}
			for p := range peers {
				if p.ID == "" || len(p.Addrs) == 0 || p.ID == b.host.ID() || p.ID.MatchesPrivateKey(privKey) {
					continue
				}
				for peer := range seenPeers {
					key, err := p.ID.ExtractPublicKey()
					if err == nil && peer.MatchesPublicKey(key) {
						continue
					} else if err != nil {
						log.Warn("Failed to extract public key from peer", "error", err.Error())
					}
				}
				seenPeers[p.ID] = struct{}{}
				peerc <- p
			}
		}
	}(b.opts.Rendezvous)

	log.Debug("Searching for results from a previous election")
	electionResults, err := b.host.DHT().SearchValue(electionContext, resultKey)
	if err != nil {
		defer b.close()
		return false, nil, fmt.Errorf("failed to search DHT for election results: %w", err)
	}

	// Do leader election
	var votemu sync.Mutex
	seenvotes := make(map[uuid.UUID]struct{})
	seenvotes[b.localUUID] = struct{}{}

	log.Info("Starting leader election")
	electionTimeout := time.After(b.opts.ElectionTimeout)

LeaderElect:
	for {
		select {
		case <-ctx.Done():
			return false, nil, ctx.Err()
		case <-electionContext.Done():
			log.Info("Election finished", "num-voters", len(seenvotes))
			break LeaderElect
		case <-electionTimeout:
			electionCancel()
			log.Info("Election timed out", "num-voters", len(seenvotes))
			break LeaderElect
		case result := <-electionResults:
			if len(result) == 0 {
				continue
			}
			// Verify the signature of the value
			log.Debug("Found a previous election result", "result", hash(result))
			leader, err := signer.deterministicVerify(result)
			if err != nil {
				log.Warn("Invalid election result", "error", err.Error())
				continue
			}
			defer electionCancel()
			// This is a valid election result. Use it.
			b.leaderUUID = leader
			rt = newRoundTripperWithHostAndCloseFunc[v1.JoinRequest, v1.JoinResponse](b.host, RoundTripOptions{
				Rendezvous: hash(result),
				Method:     v1.Membership_Join_FullMethodName,
			}, b.close)
			return false, rt, transport.ErrAlreadyBootstrapped
		case voter := <-acceptc:
			func(conn network.Stream) {
				defer conn.Close()
				votemu.Lock()
				defer votemu.Unlock()
				rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
				vlog := log.With("remote-host-id", conn.Conn().RemotePeer().String())
				vlog.Debug("Received a vote connection from a peer")
				remoteVote, err := rw.ReadBytes('\x00')
				if err != nil {
					vlog.Error("Failed to read vote", "error", err.Error())
					return
				}
				remoteVote = remoteVote[:len(remoteVote)-1]
				remoteUUID, err := signer.verify(remoteVote)
				if err != nil {
					vlog.Warn("Invalid election vote", "error", err.Error())
					return
				}
				vlog = vlog.With("remote-vote", remoteUUID.String())
				vlog.Debug("Vote has a valid signature")
				seenvotes[remoteUUID] = struct{}{}
				// Write our vote to the wire
				vlog.Debug("Sending our vote to remote peer")
				_, err = rw.Write(append(vote, '\x00'))
				if err != nil {
					vlog.Error("Failed to write vote", "error", err.Error())
					return
				}
				err = rw.Flush()
				if err != nil {
					vlog.Error("Failed to flush vote", "error", err.Error())
					return
				}
				vlog.Info("Sent our vote to remote peer")
				if len(seenvotes) == len(b.opts.NodeIDs)+1 {
					vlog.Info("All votes received, stopping election early")
					electionCancel()
				}
			}(voter)
		case voter := <-peerc:
			func() {
				votemu.Lock()
				defer votemu.Unlock()
				vlog := log.With("remote-host-id", voter.ID)
				vlog.Debug("Found a voter to dial")
				ctx := context.Background()
				if b.opts.Host.ConnectTimeout > 0 {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, b.opts.Host.ConnectTimeout)
					defer cancel()
				}
				conn, err := b.host.Host().NewStream(ctx, voter.ID, BootstrapProtocol)
				if err != nil {
					vlog.Debug("Failed to create stream to voter", "error", err.Error())
					return
				}
				defer conn.Close()
				rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
				vlog.Debug("Sending our vote to remote peer")
				_, err = rw.Write(append(vote, '\x00'))
				if err != nil {
					vlog.Error("Failed to write vote", "error", err.Error())
					return
				}
				err = rw.Flush()
				if err != nil {
					vlog.Error("Failed to flush vote", "error", err.Error())
					return
				}
				vlog.Info("Sent our vote to remote peer")
				// Read their vote off the wire
				vlog.Debug("Reading vote from remote peer")
				resp, err := rw.ReadBytes('\x00')
				if err != nil {
					if err != io.EOF || len(resp) == 0 {
						vlog.Error("Failed to read vote", "error", err.Error())
						return
					}
				}
				resp = resp[:len(resp)-1]
				conn.Close()
				remoteUUID, err := signer.verify(resp)
				if err != nil {
					vlog.Warn("Invalid election vote", "error", err.Error())
					return
				}
				vlog = vlog.With("remote-vote", remoteUUID.String())
				vlog.Info("Received vote from peer with a valid signature")
				seenvotes[remoteUUID] = struct{}{}
				if len(seenvotes) == len(b.opts.NodeIDs)+1 {
					vlog.Info("All votes received, stopping election early")
					electionCancel()
				}
			}()
		}
	}

	numVotes := len(seenvotes)

	// Determine the leader by who has the largest vote
	if numVotes == 0 {
		log.Warn("No other voters found within the election period")
	}
	var leaderUUID uuid.UUID = b.localUUID
	for vote := range seenvotes {
		if vote.String() > leaderUUID.String() {
			leaderUUID = vote
		}
	}
	if leaderUUID.String() == b.localUUID.String() {
		// Start an announcer for the others to join
		log.Info("We were elected leader", "voters", numVotes)
		isLeader = true
	} else {
		log.Info("We were not elected leader", "leader", leaderUUID.String(), "voters", numVotes)
	}
	b.leaderUUID = leaderUUID

	// The winner signs their UUID and writes it to the DHT at a deterministic
	// hash of the initial rendezvous string. This is the string that the others
	// will use to join the cluster. Others performing leader election will
	// see this value and assume the cluster was "already bootstrapped" and
	// receive a transport to the leader. The key's value is signed by a
	// pre-shared key that is known to all nodes in the cluster.
	joinPSK, err := signer.deterministicSign(leaderUUID)
	if err != nil {
		defer b.close()
		return false, nil, fmt.Errorf("failed to sign leader UUID: %w", err)
	}
	joinRendezvous := hash(joinPSK)

	// Everyone writes the signed rendezvous string to the DHT at the result key
	log.Debug("Writing join PSK to the DHT", "key", resultKey, "hashed", joinRendezvous)
	err = b.host.DHT().PutValue(ctx, resultKey, joinPSK)
	if err != nil {
		defer b.close()
		return false, nil, fmt.Errorf("failed to put join PSK to DHT: %w", err)
	}

	// If we were elected leader, we write the join PSK to the DHT and start
	// an announcer for the others to join.
	if isLeader || numVotes == 0 {
		log.Info("Starting leader announcer", "rendezvous", joinRendezvous)
		// Start an announcer for the others to join
		err = b.announcer.AnnounceToDHT(context.Background(), AnnounceOptions{
			Rendezvous:  joinRendezvous,
			AnnounceTTL: b.opts.Linger,
			Method:      v1.Membership_Join_FullMethodName,
			Host:        b.host,
		})
		if err != nil {
			defer b.close()
			return false, nil, fmt.Errorf("failed to start announcer: %w", err)
		}
		go func() {
			defer b.close()
			log.Info("Waiting for linger period so people can join")
			<-time.After(b.opts.Linger)
			log.Info("Leaving the bootstrap rendezvous point")
			if err := b.announcer.LeaveDHT(ctx, joinRendezvous); err != nil {
				log.Error("Failed to leave rendezvous point", "error", err.Error())
			}
		}()
		return
	}
	// Create a transport to the leader with the signed rendezvous string.
	rt = newRoundTripperWithHostAndCloseFunc[v1.JoinRequest, v1.JoinResponse](b.host, RoundTripOptions{
		Rendezvous: joinRendezvous,
		Method:     v1.Membership_Join_FullMethodName,
	}, b.close)
	return
}

const uuidSize = len(uuid.UUID{})

type electionSigner struct {
	signer crypto.PSK
}

func (s *electionSigner) deterministicSign(value uuid.UUID) ([]byte, error) {
	return s.signer.DeterministicSign(value[:])
}

func (s *electionSigner) deterministicVerify(value []byte) (uuid.UUID, error) {
	sigSize := s.signer.DeterministicSignatureSize()
	if len(value) != uuidSize+sigSize {
		return uuid.UUID{}, fmt.Errorf("invalid data length, got %d bytes, expected %d bytes", len(value), uuidSize+sigSize)
	}
	remoteUUID := value[:len(value)-sigSize]
	sig := value[len(value)-sigSize:]
	err := s.signer.DeterministicVerify(remoteUUID, sig)
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("invalid signature: %w", err)
	}
	var uu uuid.UUID
	copy(uu[:], remoteUUID)
	return uu, nil
}

func (s *electionSigner) sign(value uuid.UUID) ([]byte, error) {
	sig, err := s.signer.Sign(value[:])
	if err != nil {
		return nil, err
	}
	return append(value[:], sig...), nil
}

func (s *electionSigner) verify(value []byte) (uuid.UUID, error) {
	sigSize := s.signer.SignatureSize()
	if len(value) != uuidSize+sigSize {
		return uuid.UUID{}, fmt.Errorf("invalid data length, got %d bytes, expected %d bytes", len(value), uuidSize+sigSize)
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
}

func newElectionValidator() record.Validator {
	return &electionValidator{}
}

// Validate validates the given record, returning an error if it's
// invalid (e.g., expired, signed by the wrong key, etc.).
func (e *electionValidator) Validate(key string, value []byte) error {
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
		if string(val) > string(values[largest]) {
			largest = i
		}
	}
	return largest, nil
}
