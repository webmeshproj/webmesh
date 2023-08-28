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

// Package rbac contains utilities for evaluating requests against
// roles.
package rbac

import (
	"fmt"

	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/meshdb/rbac"
	"github.com/webmeshproj/webmesh/pkg/services/leaderproxy"
	"github.com/webmeshproj/webmesh/pkg/storage"
)

// Evaluator is an interface for evaluating actions.
type Evaluator interface {
	// Evaluate returns true if the given actions are allowed for the
	// peer information provided in the context.
	Evaluate(ctx context.Context, actions Actions) (bool, error)
	// IsSecure returns true if the evaluator is secure.
	IsSecure() bool
}

// Action is a convenience type for an action.
type Action v1.RBACAction

// Actions is a convenience type for a list of actions.
type Actions []*Action

func (a Actions) For(resource string) Actions {
	var actions Actions
	for _, action := range a {
		actions = append(actions, action.For(resource))
	}
	return actions
}

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
func NewStoreEvaluator(store storage.MeshStorage) Evaluator {
	return &storeEvaluator{rbac: rbac.New(store)}
}

type storeEvaluator struct {
	rbac rbac.RBAC
}

func (s *storeEvaluator) IsSecure() bool {
	return true
}

// Evaluate returns true if the given action is allowed for the peer information provided in the context.
func (s *storeEvaluator) Evaluate(ctx context.Context, actions Actions) (bool, error) {
	var peerName string
	if proxiedFor, ok := leaderproxy.ProxiedFor(ctx); ok {
		peerName = proxiedFor
	} else {
		peerName, ok = context.AuthenticatedCallerFrom(ctx)
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
	for _, action := range actions {
		if !nodeRoles.Eval(action.action()) && !userRoles.Eval(action.action()) {
			return false, nil
		}
	}
	return true, nil
}

// NewNoopEvaluator returns an evaluator that always returns true.
func NewNoopEvaluator() Evaluator {
	return &noopEvaluator{}
}

type noopEvaluator struct{}

// Evaluate returns true if the given action is allowed for the peer information provided in the context.
func (n *noopEvaluator) Evaluate(ctx context.Context, actions Actions) (bool, error) {
	return true, nil
}

func (s *noopEvaluator) IsSecure() bool {
	return false
}
