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
	"bytes"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/google/uuid"
	record "github.com/libp2p/go-libp2p-record"
	dcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	dutil "github.com/libp2p/go-libp2p/p2p/discovery/util"
	v1 "github.com/webmeshproj/api/v1"
	"golang.org/x/crypto/sha3"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/meshnet/transport"
	"github.com/webmeshproj/webmesh/pkg/storage/errors"
)

const LineFeed = '\x00'

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
	HostOptions HostOptions
	// Host is a pre-started host to use for the transport.
	Host host.Host
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
	if opts.Host != nil {
		host := wrapHost(opts.Host)
		dht, err := NewDHT(ctx, host.Host(), opts.HostOptions.BootstrapPeers, opts.HostOptions.ConnectTimeout)
		if err != nil {
			return nil, err
		}
		h := &discoveryHost{
			h:   host,
			dht: dht,
		}
		return newBootstrapTransportWithClose(h, announcer, opts, uu, func() {
			err := dht.Close()
			if err != nil {
				context.LoggerFrom(ctx).Error("Failed to close DHT", "error", err.Error())
			}
		}), nil
	}
	host, err := NewDiscoveryHost(ctx, opts.HostOptions)
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
func NewBootstrapTransportWithHost(host DiscoveryHost, announcer Announcer, opts BootstrapOptions) (BootstrapTransport, error) {
	uu, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}
	return newBootstrapTransportWithClose(host, announcer, opts, uu, func() {}), nil
}

func newBootstrapTransportWithClose(host DiscoveryHost, announcer Announcer, opts BootstrapOptions, localUUID uuid.UUID, close func()) BootstrapTransport {
	return &bootstrapTransport{
		opts:      opts,
		host:      host,
		localUUID: localUUID,
		announcer: announcer,
		signer:    &electionSigner{signer: opts.Signer},
		seenVotes: map[uuid.UUID]struct{}{
			localUUID: {},
		},
		electionCancel: func() {},
		close:          close,
	}
}

type bootstrapTransport struct {
	opts                  BootstrapOptions
	host                  DiscoveryHost
	privKey               dcrypto.PrivKey
	localUUID, leaderUUID uuid.UUID
	announcer             Announcer
	signer                *electionSigner
	seenVotes             map[uuid.UUID]struct{}
	voteData              []byte
	electionCancel        func()
	close                 func()
	mu                    sync.Mutex
}

func (b *bootstrapTransport) UUID() uuid.UUID {
	return b.localUUID
}

func (b *bootstrapTransport) LeaderUUID() uuid.UUID {
	return b.leaderUUID
}

func (b *bootstrapTransport) LeaderElect(ctx context.Context) (isLeader bool, rt transport.JoinRoundTripper, err error) {
	b.privKey = b.host.Host().Peerstore().PrivKey(b.host.Host().ID())
	hash := func(value []byte) string {
		return fmt.Sprintf("%x", sha3.Sum224(value))
	}
	electionContext, electionCancel := context.WithCancel(ctx)
	b.electionCancel = electionCancel

	signer := electionSigner{signer: b.opts.Signer}
	b.host.DHT().Validator = newElectionValidator()
	resultKey := hash([]byte(b.opts.Rendezvous))
	vote, err := signer.sign(b.localUUID)
	if err != nil {
		defer b.close()
		return false, nil, fmt.Errorf("failed to sign our UUID: %w", err)
	}
	b.voteData = append(vote, LineFeed)
	log := context.LoggerFrom(ctx).With(
		"rendezvous", b.opts.Rendezvous,
		"host-id", b.host.ID(),
		"result-key", resultKey,
		"local-uuid", b.localUUID,
	)

	log.Debug("Advertising leader election and setting up stream handler")
	acceptc := make(chan network.Stream, 100)
	b.host.Host().SetStreamHandler(BootstrapProtocol, func(s network.Stream) {
		acceptc <- s
	})
	listenCtx, listenCancel := context.WithCancel(context.Background())
	routingDiscovery := drouting.NewRoutingDiscovery(b.host.DHT())
	dutil.Advertise(listenCtx, routingDiscovery, b.opts.Rendezvous, discovery.TTL(b.opts.ElectionTimeout))

	discoveryCtx, discoveryCancel := context.WithCancel(context.Background())
	peerc := make(chan peer.AddrInfo, 100)
	go b.discoverPeers(discoveryCtx, routingDiscovery, peerc)
	defer discoveryCancel()

	// Do leader election
	log.Info("Starting leader election")
	electionTimeout := time.After(b.opts.ElectionTimeout)

LeaderElect:
	for {
		select {
		case <-ctx.Done():
			return false, nil, ctx.Err()
		case <-electionContext.Done():
			log.Info("Election finished", "num-voters", len(b.seenVotes))
			break LeaderElect
		case <-electionTimeout:
			electionCancel()
			log.Info("Election timed out", "num-voters", len(b.seenVotes))
			break LeaderElect
		case stream := <-acceptc:
			go b.handleIncomingStream(context.WithLogger(ctx, log), stream, "")
		case voter := <-peerc:
			electionResult := b.handleDiscoveredPeer(context.WithLogger(ctx, log), voter)
			if electionResult != "" {
				// Go ahead and use the decided rendezvous point
				defer listenCancel()
				log.Info("Joining the cluster", "rendezvous", electionResult)
				rt = newRoundTripperWithHostAndCloseFunc[v1.JoinRequest, v1.JoinResponse](b.host, RoundTripOptions{
					Rendezvous: electionResult,
					Method:     v1.Membership_Join_FullMethodName,
				}, b.close)
				return false, rt, errors.ErrAlreadyBootstrapped
			}
		}
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	numVotes := len(b.seenVotes)

	// Determine the leader by who has the largest vote
	if numVotes == 0 {
		log.Warn("No other voters found within the election period")
	}
	var leaderUUID uuid.UUID = b.localUUID
	for vote := range b.seenVotes {
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
		defer listenCancel()
		defer b.close()
		return false, nil, fmt.Errorf("failed to sign leader UUID: %w", err)
	}
	joinRendezvous := hash(joinPSK)

	// If we were elected leader, we start an announcer for the others to join
	if isLeader || numVotes == 0 {
		log.Info("Starting leader announcer", "rendezvous", joinRendezvous)
		// Start an announcer for the others to join
		err = b.announcer.AnnounceToDHT(context.Background(), AnnounceOptions{
			Rendezvous:  joinRendezvous,
			AnnounceTTL: b.opts.Linger,
			Method:      v1.Membership_Join_FullMethodName,
			Host:        b.host.Host(),
		})
		if err != nil {
			defer b.close()
			return false, nil, fmt.Errorf("failed to start announcer: %w", err)
		}
		go func() {
			defer b.close()
			defer listenCancel()
			log.Info("Waiting for linger period so people can join")
			expired := time.After(b.opts.Linger)
		Linger:
			for {
				select {
				case <-ctx.Done():
					break Linger
				case <-expired:
					break Linger
				case c := <-acceptc:
					go b.handleIncomingStream(ctx, c, joinRendezvous)
				}
			}
			<-time.After(b.opts.Linger)
			log.Info("Leaving the bootstrap rendezvous point")
			if err := b.announcer.LeaveDHT(ctx, joinRendezvous); err != nil {
				log.Error("Failed to leave rendezvous point", "error", err.Error())
			}
		}()
		return
	}
	defer listenCancel()
	// Create a transport to the leader with the signed rendezvous string.
	rt = newRoundTripperWithHostAndCloseFunc[v1.JoinRequest, v1.JoinResponse](b.host, RoundTripOptions{
		Rendezvous: joinRendezvous,
		Method:     v1.Membership_Join_FullMethodName,
	}, b.close)
	return
}

func (b *bootstrapTransport) discoverPeers(ctx context.Context, discovery *drouting.RoutingDiscovery, peerc chan peer.AddrInfo) {
	log := context.LoggerFrom(ctx)
	seenPeers := make(map[peer.ID]struct{})
	defer close(peerc)
FindPeers:
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		log.Debug("Searching for remote voters")
		peers, err := discovery.FindPeers(ctx, b.opts.Rendezvous)
		if err != nil {
			log.Warn("Failed to find peers", "error", err.Error())
			return
		}
		for {
			select {
			case <-ctx.Done():
				return
			case p, ok := <-peers:
				if !ok {
					continue FindPeers
				}
				key, err := p.ID.ExtractPublicKey()
				if err != nil {
					log.Warn("Failed to extract public key from peer", "error", err.Error())
					continue
				}
				if p.ID == "" || len(p.Addrs) == 0 || p.ID == b.host.ID() || key.Equals(b.privKey.GetPublic()) {
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
	}
}

func (b *bootstrapTransport) handleIncomingStream(ctx context.Context, stream network.Stream, electionResult string) {
	defer b.checkFinished(ctx)
	defer stream.Close()
	vlog := context.LoggerFrom(ctx).With("remote-host-id", stream.Conn().RemotePeer().String())
	rw := bufio.NewReadWriter(bufio.NewReader(stream), bufio.NewWriter(stream))
	vlog.Debug("Received a vote connection from a peer")
	remoteVote, err := rw.ReadBytes(LineFeed)
	if err != nil {
		if err != io.EOF || len(remoteVote) == 0 {
			vlog.Error("Failed to read vote", "error", err.Error())
			return
		}
	}
	remoteVote = remoteVote[:len(remoteVote)-1]
	remoteUUID, err := b.signer.verify(remoteVote)
	if err != nil {
		vlog.Warn("Invalid election vote", "error", err.Error())
		return
	}
	vlog = vlog.With("remote-vote", remoteUUID.String())
	vlog.Info("Received new vote with a valid signature")
	if electionResult == "" {
		// The election is still ongoing, send our vote
		vlog.Info("Sending our vote to remote peer")
		_, err = rw.Write(b.voteData)
		if err != nil {
			vlog.Error("Failed to write vote", "error", err.Error())
			return
		}
		err = rw.Flush()
		if err != nil {
			vlog.Error("Failed to flush vote", "error", err.Error())
			return
		}
		vlog.Debug("Sent our vote to remote peer")
		b.mu.Lock()
		b.seenVotes[remoteUUID] = struct{}{}
		b.mu.Unlock()
		return
	}
	// We already have an election result, notify the remote peer of it.
	vlog.Info("Election already has a result, sending it to remote peer")
	res := append([]byte("result:"), []byte(electionResult)...)
	_, err = rw.Write(append(res, LineFeed))
	if err != nil {
		vlog.Error("Failed to write election result", "error", err.Error())
		return
	}
	err = rw.Flush()
	if err != nil {
		vlog.Error("Failed to flush election result", "error", err.Error())
		return
	}
	vlog.Info("Sent election result to remote peer")
}

func (b *bootstrapTransport) handleDiscoveredPeer(ctx context.Context, peer peer.AddrInfo) (electionResult string) {
	defer b.checkFinished(ctx)
	vlog := context.LoggerFrom(ctx).With("remote-host-id", peer.ID)
	connectctx := context.Background()
	if b.opts.HostOptions.ConnectTimeout > 0 {
		var cancel context.CancelFunc
		connectctx, cancel = context.WithTimeout(connectctx, b.opts.HostOptions.ConnectTimeout)
		defer cancel()
	}
	conn, err := b.host.Host().NewStream(connectctx, peer.ID, BootstrapProtocol)
	if err != nil {
		vlog.Debug("Failed to create stream to voter", "error", err.Error())
		return
	}
	defer conn.Close()
	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
	vlog.Info("Sending our vote to remote peer")
	_, err = rw.Write(b.voteData)
	if err != nil {
		vlog.Error("Failed to write vote", "error", err.Error())
		return
	}
	err = rw.Flush()
	if err != nil {
		vlog.Error("Failed to flush vote", "error", err.Error())
		return
	}
	vlog.Debug("Sent our vote to remote peer")
	vlog.Debug("Reading vote from remote peer")
	resp, err := rw.ReadBytes(LineFeed)
	if err != nil {
		if err != io.EOF || len(resp) == 0 {
			vlog.Error("Failed to read vote", "error", err.Error())
			return
		}
	}
	resp = resp[:len(resp)-1]
	if bytes.HasPrefix(resp, []byte("result:")) {
		// We were too late to the election and there is
		// already a rendezvous point decided.
		vlog.Info("Election already has a result, joining the cluster")
		return string(resp[len("result:"):])
	}
	remoteUUID, err := b.signer.verify(resp)
	if err != nil {
		vlog.Warn("Invalid election vote", "error", err.Error())
		return
	}
	vlog = vlog.With("remote-vote", remoteUUID.String())
	b.mu.Lock()
	vlog.Info("Received vote from peer with a valid signature")
	b.seenVotes[remoteUUID] = struct{}{}
	b.mu.Unlock()
	return ""
}

func (b *bootstrapTransport) checkFinished(ctx context.Context) {
	b.mu.Lock()
	defer b.mu.Unlock()
	vlog := context.LoggerFrom(ctx)
	if len(b.seenVotes) == len(b.opts.NodeIDs)+1 {
		vlog.Info("All votes received, cancelling election")
		b.electionCancel()
	}
}

const uuidSize = len(uuid.UUID{})

type electionSigner struct {
	signer crypto.PSK
}

func (s *electionSigner) deterministicSign(value uuid.UUID) ([]byte, error) {
	return s.signer.DeterministicSign(value[:])
}

func (s *electionSigner) sign(value uuid.UUID) ([]byte, error) {
	sig, err := s.signer.Sign(value[:])
	if err != nil {
		return nil, err
	}
	return append(value[:], sig...), nil
}

func (s *electionSigner) verify(value []byte) (uuid.UUID, error) {
	if len(value) <= uuidSize {
		return uuid.UUID{}, fmt.Errorf("invalid vote size: %d", len(value))
	}
	remoteUUID := value[:uuidSize]
	sig := value[uuidSize:]
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
