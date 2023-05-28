/*
Copyright 2023.

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

// Package raftacls contains the interface for managing Raft ACLs and
// determing if a user has access to a role in the cluster.
package raftacls

import (
	"context"
	"database/sql"
	"regexp"
	"strings"
	"time"

	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/node/pkg/meshdb"
	"github.com/webmeshproj/node/pkg/meshdb/models/raftdb"
)

// ErrACLNotFound is returned when an ACL is not found.
var ErrACLNotFound = sql.ErrNoRows

// RaftACLs is the interface for managing Raft ACLs.
type RaftACLs interface {
	// CanVote returns true if the node is allowed to vote in the cluster.
	CanVote(ctx context.Context, nodeID string) (bool, error)
	// PutACL add or updates a Raft ACL.
	PutACL(ctx context.Context, acl *ACL) error
	// DeleteACL deletes a Raft ACL.
	DeleteACL(ctx context.Context, name string) error
	// GetACL returns a Raft ACL.
	GetACL(ctx context.Context, name string) (*ACL, error)
	// ListACLs returns a list of Raft ACLs.
	ListACLs(ctx context.Context) ([]*ACL, error)
}

// ACL is a Raft ACL.
type ACL struct {
	// Name is the name of the ACL.
	Name string
	// NodePatterns is a list of node patterns that the ACL applies to.
	NodePatterns []string
	// CanVote is true if the node is allowed to vote in the cluster.
	CanVote bool
	// CreatedAt is the time the ACL was created.
	CreatedAt time.Time
	// UpdatedAt is the time the ACL was last updated.
	UpdatedAt time.Time
}

// Matches returns true if the node matches the ACL.
func (a *ACL) Matches(nodeID string) bool {
	for _, pattern := range a.NodePatterns {
		pattern = strings.ReplaceAll(pattern, "*", ".*")
		if ok, _ := regexp.MatchString(pattern, nodeID); ok {
			return true
		}
	}
	return false
}

// New creates a new Raft ACLs.
func New(store meshdb.Store) RaftACLs {
	return &raftACLs{
		store: store,
	}
}

type raftACLs struct {
	store meshdb.Store
}

// CanVote returns true if the node is allowed to vote in the cluster.
func (r *raftACLs) CanVote(ctx context.Context, nodeID string) (bool, error) {
	acls, err := r.ListACLs(ctx)
	if err != nil {
		return false, err
	}
	if len(acls) == 0 {
		return true, nil
	}
	for _, acl := range acls {
		if acl.Matches(nodeID) {
			return acl.CanVote, nil
		}
	}
	return false, nil
}

// PutACL add or updates a Raft ACL.
func (r *raftACLs) PutACL(ctx context.Context, acl *ACL) error {
	return raftdb.New(r.store.DB()).PutRaftACL(ctx, raftdb.PutRaftACLParams{
		Name:  acl.Name,
		Nodes: strings.Join(acl.NodePatterns, ","),
		Action: func() int64 {
			if acl.CanVote {
				return int64(v1.ACLAction_ALLOW.Number())
			}
			return int64(v1.ACLAction_DENY.Number())
		}(),
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	})
}

// DeleteACL deletes a Raft ACL.
func (r *raftACLs) DeleteACL(ctx context.Context, name string) error {
	return raftdb.New(r.store.DB()).DeleteRaftACL(ctx, name)
}

// GetACL returns a Raft ACL.
func (r *raftACLs) GetACL(ctx context.Context, name string) (*ACL, error) {
	acl, err := raftdb.New(r.store.ReadDB()).GetRaftACL(ctx, name)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrACLNotFound
		}
		return nil, err
	}
	return dbACLtoACL(acl), nil
}

// ListACLs returns a list of Raft ACLs.
func (r *raftACLs) ListACLs(ctx context.Context) ([]*ACL, error) {
	acls, err := raftdb.New(r.store.ReadDB()).ListRaftACLs(ctx)
	if err != nil {
		if err == sql.ErrNoRows {
			return []*ACL{}, nil
		}
		return nil, err
	}
	out := make([]*ACL, len(acls))
	for i, acl := range acls {
		out[i] = dbACLtoACL(acl)
	}
	return out, nil
}

func dbACLtoACL(acl raftdb.RaftAcl) *ACL {
	return &ACL{
		Name:         acl.Name,
		NodePatterns: strings.Split(acl.Nodes, ","),
		CanVote:      acl.Action == int64(v1.ACLAction_ALLOW.Number()),
		CreatedAt:    acl.CreatedAt,
		UpdatedAt:    acl.UpdatedAt,
	}
}
