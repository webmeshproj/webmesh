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

// Package rbac contains utilities for evaluating requests against
// roles.
package rbac

import (
	"context"
	"fmt"

	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/node/pkg/meshdb"
	rbacdb "github.com/webmeshproj/node/pkg/meshdb/rbac"
	"github.com/webmeshproj/node/pkg/services/leaderproxy"
	"github.com/webmeshproj/node/pkg/services/util"
)

// Evaluator is an interface for evaluating actions.
type Evaluator interface {
	// Evaluate returns true if the given action is allowed for the
	// peer information provided in the context.
	Evaluate(ctx context.Context, action *Action) (bool, error)
}

// Action is a convenience type for an action.
type Action v1.RBACAction

// For returns a copy of this action for the given resource name.
func (a *Action) For(resource string) *Action {
	return &Action{
		Verb:         a.Verb,
		Resource:     a.Resource,
		ResourceName: resource,
	}
}

// action returns the underlying v1.Action.
func (a *Action) action() *v1.RBACAction {
	return (*v1.RBACAction)(a)
}

// NewStoreEvaluator returns a ActionEvaluator that evaluates actions
// against the roles in the given store.
func NewStoreEvaluator(store meshdb.Store) Evaluator {
	return &storeEvaluator{rbac: rbacdb.New(store)}
}

type storeEvaluator struct {
	rbac rbacdb.RBAC
}

// Evaluate returns true if the given action is allowed for the peer information provided in the context.
func (s *storeEvaluator) Evaluate(ctx context.Context, action *Action) (bool, error) {
	var peerName string
	if proxiedFor, ok := leaderproxy.ProxiedFor(ctx); ok {
		peerName = proxiedFor
	} else {
		peerName, ok = util.PeerFromContext(ctx)
		if !ok {
			return false, fmt.Errorf("no peer information in context")
		}
	}
	if peerName == "" {
		return false, fmt.Errorf("no peer information in context")
	}
	// We treat nodes and users as the same entity for the purpose of authorization.
	nodeRoles, err := s.rbac.ListNodeRoles(ctx, peerName)
	if err != nil {
		return false, err
	}
	userRoles, err := s.rbac.ListUserRoles(ctx, peerName)
	if err != nil {
		return false, err
	}
	return nodeRoles.Eval(action.action()) ||
		userRoles.Eval(action.action()), nil
}

// NewNoopEvaluator returns an evaluator that always returns true.
func NewNoopEvaluator() Evaluator {
	return &noopEvaluator{}
}

type noopEvaluator struct{}

// Evaluate returns true if the given action is allowed for the peer information provided in the context.
func (n *noopEvaluator) Evaluate(ctx context.Context, action *Action) (bool, error) {
	return true, nil
}
