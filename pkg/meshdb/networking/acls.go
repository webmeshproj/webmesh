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

package networking

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"

	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/webmeshproj/webmesh/pkg/context"
	peergraph "github.com/webmeshproj/webmesh/pkg/meshdb/graph"
	"github.com/webmeshproj/webmesh/pkg/meshdb/rbac"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/storageutil"
)

// ValidateACL validates a NetworkACL.
func ValidateACL(acl *v1.NetworkACL) error {
	if acl.GetName() == "" {
		return errors.New("acl name is required")
	}
	if !storageutil.IsValidID(acl.GetName()) {
		return errors.New("acl name must be a valid ID")
	}
	if _, ok := v1.ACLAction_name[int32(acl.GetAction())]; !ok {
		return errors.New("invalid acl action")
	}
	for _, node := range append(acl.GetSourceNodes(), acl.GetDestinationNodes()...) {
		if node == "*" {
			continue
		}
		node = strings.TrimPrefix(node, GroupReference)
		if !storageutil.IsValidID(node) {
			return fmt.Errorf("invalid source node: %s", node)
		}
	}
	for _, cidr := range append(acl.GetSourceCidrs(), acl.GetDestinationCidrs()...) {
		if cidr == "*" {
			continue
		}
		_, err := netip.ParsePrefix(cidr)
		if err != nil {
			return fmt.Errorf("invalid source cidr: %s", cidr)
		}
	}
	return nil
}

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

// ACL is a Network ACL.
type ACL struct {
	*v1.NetworkACL
	storage storage.MeshStorage
}

// Proto returns the protobuf representation of the ACL.
func (a *ACL) Proto() *v1.NetworkACL {
	return a.NetworkACL
}

// Marshal marshals the ACL to protobuf json.
func (a ACL) MarshalJSON() ([]byte, error) {
	return protojson.Marshal(a.NetworkACL)
}

// Unmarshal unmarshals the ACL from a protobuf.
func (a *ACL) UnmarshalJSON(data []byte) error {
	var acl v1.NetworkACL
	err := protojson.Unmarshal(data, &acl)
	if err != nil {
		return fmt.Errorf("unmarshal acl: %w", err)
	}
	a.NetworkACL = &acl
	return nil
}

// Equals returns whether the ACLs are equal.
func (a *ACL) Equals(other *ACL) bool {
	if a.GetName() != other.GetName() {
		return false
	}
	if a.GetPriority() != other.GetPriority() {
		return false
	}
	if a.GetAction() != other.GetAction() {
		return false
	}
	slComps := [][][]string{
		{a.GetSourceNodes(), other.GetSourceNodes()},
		{a.GetDestinationNodes(), other.GetDestinationNodes()},
		{a.GetSourceCidrs(), other.GetSourceCidrs()},
		{a.GetDestinationCidrs(), other.GetDestinationCidrs()},
	}
	for _, toCompare := range slComps {
		sort.Strings(toCompare[0])
		sort.Strings(toCompare[1])
		if !slices.Equal(toCompare[0], toCompare[1]) {
			return false
		}
	}
	return true
}

// SourcePrefixes returns the source prefixes for the ACL.
// Invalid prefixes will be ignored.
func (a *ACL) SourcePrefixes() []netip.Prefix {
	return toPrefixes(a.GetSourceCidrs())
}

// DestinationPrefixes returns the destination prefixes for the ACL.
// Invalid prefixes will be ignored.
func (a *ACL) DestinationPrefixes() []netip.Prefix {
	return toPrefixes(a.GetDestinationCidrs())
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
		context.LoggerFrom(ctx).Debug("Expanding group reference", "group", groupName)
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
		context.LoggerFrom(ctx).Debug("Expanding group reference", "group", groupName)
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

// AllowNodesToCommunicate checks if the given nodes are allowed to communicate.
func (a ACLs) AllowNodesToCommunicate(ctx context.Context, nodeA, nodeB peergraph.MeshNode) bool {
	v4action := Action{
		NetworkAction: &v1.NetworkAction{
			SrcNode: nodeA.Id,
			SrcCidr: nodeA.PrivateIpv4,
			DstNode: nodeB.Id,
			DstCidr: nodeB.PrivateIpv4,
		},
	}
	v6action := Action{
		NetworkAction: &v1.NetworkAction{
			SrcNode: nodeA.Id,
			SrcCidr: nodeA.PrivateIpv6,
			DstNode: nodeB.Id,
			DstCidr: nodeB.PrivateIpv6,
		},
	}
	return a.Accept(ctx, v4action) || a.Accept(ctx, v6action)
}

// Accept evaluates an action against the ACLs in the list. It assumes the ACLs
// are sorted by priority. The first ACL that matches the action will be used.
// If no ACL matches, the action is denied.
func (a ACLs) Accept(ctx context.Context, action Action) bool {
	for _, acl := range a {
		if acl.Matches(ctx, action) {
			context.LoggerFrom(ctx).Debug("Network ACL matches action", "action", action, "acl", acl)
			return acl.Action == v1.ACLAction_ACTION_ACCEPT
		}
	}
	context.LoggerFrom(ctx).Debug("No network ACL matches action, denying", "action", action)
	return false
}

// Matches checks if an action matches this ACL.
func (acl *ACL) Matches(ctx context.Context, action Action) bool {
	if action.GetSrcNode() != "" && len(acl.GetSourceNodes()) >= 0 {
		if !containsOrWildcardMatch(acl.GetSourceNodes(), action.GetSrcNode()) {
			return false
		}
	}
	if action.GetDstNode() != "" && len(acl.GetDestinationNodes()) >= 0 {
		if !containsOrWildcardMatch(acl.GetDestinationNodes(), action.GetDstNode()) {
			return false
		}
	}
	if action.SourcePrefix().IsValid() && len(acl.GetSourceCidrs()) > 0 {
		if !containsAddress(acl.SourcePrefixes(), action.SourcePrefix().Addr()) {
			return false
		}
	}
	if action.DestinationPrefix().IsValid() && len(acl.GetDestinationCidrs()) > 0 {
		if !containsAddress(acl.DestinationPrefixes(), action.DestinationPrefix().Addr()) {
			return false
		}
	}
	return true
}

func containsOrWildcardMatch(ss []string, s string) bool {
	for _, v := range ss {
		if v == "*" || v == s {
			return true
		}
	}
	return false
}

func containsAddress(cidrs []netip.Prefix, addr netip.Addr) bool {
	for _, cidr := range cidrs {
		if cidr.Addr().IsUnspecified() || cidr.Contains(addr) {
			return true
		}
	}
	return false
}
