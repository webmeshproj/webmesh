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

package raft

import (
	"errors"
	"io"
	"log/slog"
	"time"

	"github.com/hashicorp/raft"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/storage"
)

// ErrNotRaftMember is returned for methods that are only valid on raft members.
var ErrNotRaftMember = errors.New("not a raft member")

// NewPassthrough creates a new raft instance that is a no-op for most methods
// and uses the given Dialer for storage connections.
func NewPassthrough(dialer NodeDialer) Raft {
	return &passthroughRaft{
		dialer: dialer,
		closec: make(chan struct{}),
		log:    slog.Default().With("component", "passthrough-raft"),
	}
}

// passthroughRaft implements the raft interface, but is a no-op for most methods.
// It is used by non-raft members to allow them to expose the raft interface.
// It should later be removed in favor of less coupling between the connection
// and raft interfaces.
type passthroughRaft struct {
	dialer NodeDialer
	nodeID string
	closec chan struct{}
	log    *slog.Logger
}

func (p *passthroughRaft) Start(ctx context.Context, opts *StartOptions) error {
	p.nodeID = opts.NodeID
	return nil
}

func (p *passthroughRaft) Bootstrap(ctx context.Context, opts *BootstrapOptions) error {
	return ErrNotRaftMember
}

func (p *passthroughRaft) Storage() storage.Storage {
	return &passthroughStorage{raft: p}
}

func (p *passthroughRaft) Configuration() (raft.Configuration, error) {
	config, err := p.getConfiguration()
	if err != nil {
		return raft.Configuration{}, err
	}
	out := raft.Configuration{
		Servers: make([]raft.Server, len(config.Servers)),
	}
	for i, srv := range config.Servers {
		out.Servers[i] = raft.Server{
			ID:      raft.ServerID(srv.GetId()),
			Address: raft.ServerAddress(srv.GetAddress()),
			Suffrage: func() raft.ServerSuffrage {
				switch srv.GetSuffrage() {
				case v1.ClusterStatus_CLUSTER_LEADER:
					return raft.Voter
				case v1.ClusterStatus_CLUSTER_VOTER:
					return raft.Voter
				case v1.ClusterStatus_CLUSTER_NON_VOTER:
					return raft.Nonvoter
				default:
					return raft.Nonvoter
				}
			}(),
		}
	}
	return out, nil
}

func (p *passthroughRaft) getConfiguration() (*v1.RaftConfigurationResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := p.dialer.Dial(ctx, "")
	if err != nil {
		return nil, err
	}
	cli := v1.NewMembershipClient(c)
	config, err := cli.GetRaftConfiguration(ctx, &v1.RaftConfigurationRequest{})
	if err != nil {
		return nil, err
	}
	return config, nil
}

func (p *passthroughRaft) LastIndex() uint64 {
	return 0
}

func (p *passthroughRaft) LastAppliedIndex() uint64 {
	return 0
}

func (p *passthroughRaft) ListenPort() int {
	return 0
}

func (p *passthroughRaft) LeaderID() (string, error) {
	config, err := p.getConfiguration()
	if err != nil {
		return "", err
	}
	for _, srv := range config.Servers {
		if srv.GetSuffrage() == v1.ClusterStatus_CLUSTER_LEADER {
			return srv.GetId(), nil
		}
	}
	// Should return a better error
	return "", ErrNotRaftMember
}

func (p *passthroughRaft) IsLeader() bool {
	return false
}

func (p *passthroughRaft) IsVoter() bool {
	return false
}

func (p *passthroughRaft) IsObserver() bool {
	return false
}

func (p *passthroughRaft) AddNonVoter(ctx context.Context, id string, addr string) error {
	return ErrNotRaftMember
}

func (p *passthroughRaft) AddVoter(ctx context.Context, id string, addr string) error {
	return ErrNotRaftMember
}

func (p *passthroughRaft) DemoteVoter(ctx context.Context, id string) error {
	return ErrNotRaftMember
}

func (p *passthroughRaft) RemoveServer(ctx context.Context, id string, wait bool) error {
	return ErrNotRaftMember
}

func (p *passthroughRaft) Apply(ctx context.Context, log *v1.RaftLogEntry) (*v1.RaftApplyResponse, error) {
	return nil, ErrNotRaftMember
}

func (p *passthroughRaft) Snapshot() (*raft.SnapshotMeta, io.ReadCloser, error) {
	return nil, nil, ErrNotRaftMember
}

func (p *passthroughRaft) Barrier(ctx context.Context, timeout time.Duration) (took time.Duration, err error) {
	return 0, ErrNotRaftMember
}

func (p *passthroughRaft) Stop(ctx context.Context) error {
	close(p.closec)
	return nil
}

type passthroughStorage struct {
	raft *passthroughRaft
}

// Get returns the value of a key.
func (p *passthroughStorage) Get(ctx context.Context, key string) (string, error) {
	cli, close, err := p.newNodeClient(ctx)
	if err != nil {
		return "", err
	}
	defer close()
	resp, err := cli.Query(ctx, &v1.QueryRequest{
		Command: v1.QueryRequest_GET,
		Query:   key,
	})
	if err != nil {
		return "", err
	}
	defer p.checkErr(resp.CloseSend)
	result, err := resp.Recv()
	if err != nil {
		return "", err
	}
	if result.GetError() != "" {
		// TODO: Should find a way to type assert this error
		return "", errors.New(result.GetError())
	}
	return result.GetValue()[0], nil
}

// Put sets the value of a key. TTL is optional and can be set to 0.
func (p *passthroughStorage) Put(ctx context.Context, key, value string, ttl time.Duration) error {
	// We pass this through to the publish API. Should only be called by non-nodes wanting to publish
	// non-internal values. The server will enforce permissions and other restrictions.
	cli, close, err := p.newNodeClient(ctx)
	if err != nil {
		return err
	}
	defer close()
	_, err = cli.Publish(ctx, &v1.PublishRequest{
		Key:   key,
		Value: value,
		Ttl:   durationpb.New(ttl),
	})
	return err
}

// Delete removes a key.
func (p *passthroughStorage) Delete(ctx context.Context, key string) error {
	return ErrNotRaftMember
}

// List returns all keys with a given prefix.
func (p *passthroughStorage) List(ctx context.Context, prefix string) ([]string, error) {
	cli, close, err := p.newNodeClient(ctx)
	if err != nil {
		return nil, err
	}
	defer close()
	resp, err := cli.Query(ctx, &v1.QueryRequest{
		Command: v1.QueryRequest_LIST,
		Query:   prefix,
	})
	if err != nil {
		return nil, err
	}
	defer p.checkErr(resp.CloseSend)
	result, err := resp.Recv()
	if err != nil {
		return nil, err
	}
	if result.GetError() != "" {
		// TODO: Should find a way to type assert this error
		return nil, errors.New(result.GetError())
	}
	return result.GetValue(), nil
}

// IterPrefix iterates over all keys with a given prefix. It is important
// that the iterator not attempt any write operations as this will cause
// a deadlock.
func (p *passthroughStorage) IterPrefix(ctx context.Context, prefix string, fn storage.PrefixIterator) error {
	cli, close, err := p.newNodeClient(ctx)
	if err != nil {
		return err
	}
	defer close()
	resp, err := cli.Query(ctx, &v1.QueryRequest{
		Command: v1.QueryRequest_ITER,
		Query:   prefix,
	})
	if err != nil {
		return err
	}
	defer p.checkErr(resp.CloseSend)
	for {
		result, err := resp.Recv()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if result.GetError() == "EOF" {
			return nil
		}
		if result.GetError() != "" {
			// Should not happen
			return errors.New(result.GetError())
		}
		if err := fn(result.GetKey(), result.GetValue()[0]); err != nil {
			return err
		}
	}
}

// Snapshot returns a snapshot of the storage.
func (p *passthroughStorage) Snapshot(ctx context.Context) (io.Reader, error) {
	return nil, ErrNotRaftMember
}

// Restore restores a snapshot of the storage.
func (p *passthroughStorage) Restore(ctx context.Context, r io.Reader) error {
	return ErrNotRaftMember
}

// Subscribe will call the given function whenever a key with the given prefix is changed.
// The returned function can be called to unsubscribe.
func (p *passthroughStorage) Subscribe(ctx context.Context, prefix string, fn storage.SubscribeFunc) (func(), error) {
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		for {
			select {
			case <-p.raft.closec:
				return
			case <-ctx.Done():
				return
			default:
			}
			err := p.doSubscribe(ctx, prefix, fn)
			if err != nil {
				p.raft.log.Error("error in storage subscription, retrying in 3 seconds", "error", err.Error())
				select {
				case <-p.raft.closec:
					return
				case <-ctx.Done():
					return
				case <-time.After(3 * time.Second):
				}
				continue
			}
			return
		}
	}()
	return cancel, nil
}

func (p *passthroughStorage) doSubscribe(ctx context.Context, prefix string, fn storage.SubscribeFunc) error {
	cli, close, err := p.newNodeClient(ctx)
	if err != nil {
		return err
	}
	defer close()
	stream, err := cli.Subscribe(ctx, &v1.SubscribeRequest{
		Prefix: prefix,
	})
	if err != nil {
		return err
	}
	defer p.checkErr(stream.CloseSend)
	for {
		select {
		case <-p.raft.closec:
			return nil
		case <-ctx.Done():
			return nil
		default:
		}
		res, err := stream.Recv()
		if err != nil {
			return err
		}
		fn(res.GetKey(), string(res.GetValue()[0]))
	}
}

// Close closes the storage. This is a no-op and is handled by the passthroughRaft.
func (p *passthroughStorage) Close() error {
	return nil
}

func (p *passthroughStorage) newNodeClient(ctx context.Context) (v1.NodeClient, func(), error) {
	select {
	case <-p.raft.closec:
		return nil, nil, ErrClosed
	default:
	}
	c, err := p.raft.dialer.Dial(ctx, "")
	if err != nil {
		return nil, nil, err
	}
	return v1.NewNodeClient(c), func() { _ = c.Close() }, nil
}

func (p *passthroughStorage) checkErr(fn func() error) {
	if err := fn(); err != nil {
		p.raft.log.Error("error in storage operation", "error", err)
	}
}
