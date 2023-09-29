package types

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
	"github.com/webmeshproj/webmesh/pkg/storage/storageutil"
)

const (
	// GroupReference is the prefix of a node name that indicates it is a group reference.
	GroupReference = "group:"
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
type NetworkACLs []NetworkACL

// Len returns the length of the ACLs list.
func (a NetworkACLs) Len() int { return len(a) }

// Swap swaps the ACLs at the given indices.
func (a NetworkACLs) Swap(i, j int) { a[i], a[j] = a[j], a[i] }

// Less returns whether the ACL at index i should be sorted before the ACL at index j.
func (a NetworkACLs) Less(i, j int) bool {
	return a[i].Priority < a[j].Priority
}

// Sort sorts the ACLs by priority.
func (a NetworkACLs) Sort(direction SortDirection) {
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
func (a NetworkACLs) Proto() []*v1.NetworkACL {
	if a == nil {
		return nil
	}
	proto := make([]*v1.NetworkACL, len(a))
	for i, acl := range a {
		proto[i] = acl.Proto()
	}
	return proto
}

// AllowNodesToCommunicate checks if the given nodes are allowed to communicate.
func (a NetworkACLs) AllowNodesToCommunicate(ctx context.Context, nodeA, nodeB MeshNode) bool {
	v4action := NetworkAction{
		NetworkAction: &v1.NetworkAction{
			SrcNode: nodeA.Id,
			SrcCidr: nodeA.PrivateIpv4,
			DstNode: nodeB.Id,
			DstCidr: nodeB.PrivateIpv4,
		},
	}
	v6action := NetworkAction{
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
func (a NetworkACLs) Accept(ctx context.Context, action NetworkAction) bool {
	for _, acl := range a {
		if acl.Matches(ctx, action) {
			context.LoggerFrom(ctx).Debug("Network ACL matches action", "action", action, "acl", acl)
			return acl.Action == v1.ACLAction_ACTION_ACCEPT
		}
	}
	context.LoggerFrom(ctx).Debug("No network ACL matches action, denying", "action", action)
	return false
}

// NetworkACL is a Network ACL.
type NetworkACL struct{ *v1.NetworkACL }

// Proto returns the protobuf representation of the ACL.
func (a NetworkACL) Proto() *v1.NetworkACL {
	return a.NetworkACL
}

// Marshal marshals the ACL to protobuf json.
func (a NetworkACL) MarshalJSON() ([]byte, error) {
	return protojson.Marshal(a.NetworkACL)
}

// Unmarshal unmarshals the ACL from a protobuf.
func (a *NetworkACL) UnmarshalJSON(data []byte) error {
	var acl v1.NetworkACL
	err := protojson.Unmarshal(data, &acl)
	if err != nil {
		return fmt.Errorf("unmarshal acl: %w", err)
	}
	a.NetworkACL = &acl
	return nil
}

// Equals returns whether the ACLs are equal.
func (a NetworkACL) Equals(other NetworkACL) bool {
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
func (a NetworkACL) SourcePrefixes() []netip.Prefix {
	return toPrefixes(a.GetSourceCidrs())
}

// DestinationPrefixes returns the destination prefixes for the ACL.
// Invalid prefixes will be ignored.
func (a NetworkACL) DestinationPrefixes() []netip.Prefix {
	return toPrefixes(a.GetDestinationCidrs())
}

// Matches checks if an action matches this ACL.
func (acl NetworkACL) Matches(ctx context.Context, action NetworkAction) bool {
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
