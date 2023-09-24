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

// Package networking contains interfaces to the database models for Network ACLs and Routes.
package networking

import (
	"errors"
	"slices"
	"sort"
	"strings"

	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/meshdb/rbac"
	"github.com/webmeshproj/webmesh/pkg/storage"
)

// SortDirection is the direction to sort ACLs.
type SortDirection int

const (
	// SortDescending sorts ACLs in descending order.
	SortDescending SortDirection = iota
	// SortAscending sorts ACLs in ascending order.
	SortAscending
)

// ACLs is a list of Network ACLs. It contains methods for evaluating actions against
// contained permissions. It also allows for sorting by priority.
type ACLs []*ACL

// Len returns the length of the ACLs list.
func (a ACLs) Len() int { return len(a) }

// Swap swaps the ACLs at the given indices.
func (a ACLs) Swap(i, j int) { a[i], a[j] = a[j], a[i] }

// Less returns whether the ACL at index i should be sorted before the ACL at index j.
func (a ACLs) Less(i, j int) bool {
	return a[i].Priority < a[j].Priority
}

// Sort sorts the ACLs by priority.
func (a ACLs) Sort(direction SortDirection) {
	switch direction {
	case SortAscending:
		sort.Sort(a)
	case SortDescending:
		sort.Sort(sort.Reverse(a))
	default:
		sort.Sort(sort.Reverse(a))
	}
}

// Proto returns the protobuf representation of the ACLs.
func (a ACLs) Proto() []*v1.NetworkACL {
	if a == nil {
		return nil
	}
	proto := make([]*v1.NetworkACL, len(a))
	for i, acl := range a {
		proto[i] = acl.Proto()
	}
	return proto
}

// Expand expands any group references in the ACLs.
func (a ACLs) Expand(ctx context.Context) error {
	for _, acl := range a {
		if err := acl.Expand(ctx); err != nil {
			return err
		}
	}
	return nil
}

// ACL is a Network ACL. It contains a reference to the database for evaluating group membership.
type ACL struct {
	*v1.NetworkACL
	storage storage.MeshStorage
}

// Proto returns the protobuf representation of the ACL.
func (a *ACL) Proto() *v1.NetworkACL {
	return a.NetworkACL
}

// Expand expands any group references in the ACL.
func (a *ACL) Expand(ctx context.Context) error {
	// Expand group references in the source nodes
	var srcNodes []string
	for _, node := range a.GetSourceNodes() {
		if !strings.HasPrefix(node, GroupReference) {
			srcNodes = append(srcNodes, node)
			continue
		}
		groupName := strings.TrimPrefix(node, GroupReference)
		group, err := rbac.New(a.storage).GetGroup(ctx, groupName)
		if err != nil {
			if !errors.Is(err, rbac.ErrGroupNotFound) {
				context.LoggerFrom(ctx).Error("Failed to lookup group", "group", groupName, "error", err.Error())
				return err
			}
			// If the group doesn't exist, we'll just ignore it.
			continue
		}
		for _, subject := range group.GetSubjects() {
			if !slices.Contains(srcNodes, subject.GetName()) {
				srcNodes = append(srcNodes, subject.GetName())
			}
		}
	}
	a.SourceNodes = srcNodes
	// The same for destination nodes
	var dstNodes []string
	for _, node := range a.GetDestinationNodes() {
		if !strings.HasPrefix(node, GroupReference) {
			dstNodes = append(dstNodes, node)
			continue
		}
		groupName := strings.TrimPrefix(node, GroupReference)
		group, err := rbac.New(a.storage).GetGroup(ctx, groupName)
		if err != nil {
			if !errors.Is(err, rbac.ErrGroupNotFound) {
				context.LoggerFrom(ctx).Error("Failed to lookup group", "group", groupName, "error", err.Error())
				return err
			}
			// If the group doesn't exist, we'll just ignore it.
			continue
		}
		for _, subject := range group.GetSubjects() {
			if !slices.Contains(dstNodes, subject.GetName()) {
				dstNodes = append(dstNodes, subject.GetName())
			}
		}
	}
	a.DestinationNodes = dstNodes
	return nil
}

// Accept evaluates an action against the ACLs in the list. It assumes the ACLs
// are sorted by priority. The first ACL that matches the action will be used.
// If no ACL matches, the action is denied.
func (a ACLs) Accept(ctx context.Context, action *v1.NetworkAction) bool {
	if a == nil {
		return false
	}
	for _, acl := range a {
		if acl.Matches(ctx, action) {
			return acl.Action == v1.ACLAction_ACTION_ACCEPT
		}
	}
	return false
}

// Matches checks if an action matches this ACL. If a database query fails it will log the
// error and return false.
func (acl *ACL) Matches(ctx context.Context, action *v1.NetworkAction) bool {
	if action.GetSrcNode() != "" {
		if len(acl.GetSourceNodes()) >= 0 {
			if !containsOrWildcardMatch(acl.GetSourceNodes(), action.GetSrcNode()) {
				return false
			}
		}
	}
	if action.GetDstNode() != "" {
		if len(acl.GetDestinationNodes()) >= 0 {
			if !containsOrWildcardMatch(acl.GetDestinationNodes(), action.GetDstNode()) {
				return false
			}
		}
	}
	if action.GetSrcCidr() != "" {
		if len(acl.GetSourceCidrs()) >= 0 {
			if !containsOrWildcardMatch(acl.GetSourceCidrs(), action.GetSrcCidr()) {
				return false
			}
		}
	}
	if action.GetDstCidr() != "" {
		if len(acl.GetDestinationCidrs()) >= 0 {
			if !containsOrWildcardMatch(acl.GetDestinationCidrs(), action.GetDstCidr()) {
				return false
			}
		}
	}
	return true
}

func containsOrWildcardMatch(ss []string, s string) bool {
	for _, v := range ss {
		if v == "*" {
			return true
		} else if strings.Contains(v, "*") {
			if strings.HasPrefix(v, "*") {
				if strings.HasSuffix(s, strings.TrimPrefix(v, "*")) {
					return true
				}
			} else if strings.HasSuffix(v, "*") {
				if strings.HasPrefix(s, strings.TrimSuffix(v, "*")) {
					return true
				}
			} else {
				parts := strings.Split(v, "*")
				if strings.HasPrefix(s, parts[0]) && strings.HasSuffix(s, parts[1]) {
					return true
				}
			}
		} else if v == s {
			return true
		}
	}
	return false
}
