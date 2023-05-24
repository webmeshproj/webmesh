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

package leaderproxy

import (
	"context"

	v1 "gitlab.com/webmesh/api/v1"
	"google.golang.org/grpc/metadata"
)

const (
	// PreferLeaderMeta is the metadata key for the Prefer-Leader header.
	PreferLeaderMeta = "prefer-leader"
)

// MethodPolicy defines the policy for routing requests to the leader.
type MethodPolicy int

const (
	// RequireLeader requires that the request is routed to the leader.
	RequireLeader MethodPolicy = iota
	// AllowNonLeader allows the request to be routed to a non-leader.
	AllowNonLeader
	// RequireLocal requires that the request is routed to the local node.
	RequireLocal
)

// MethodPolicyMap is a map of method names to their MethodPolicy.
var MethodPolicyMap = map[string]MethodPolicy{
	v1.Node_Join_FullMethodName:               RequireLeader,
	v1.Node_Leave_FullMethodName:              RequireLeader,
	v1.Mesh_GetNode_FullMethodName:            AllowNonLeader,
	v1.Mesh_ListNodes_FullMethodName:          AllowNonLeader,
	v1.Node_GetFeatures_FullMethodName:        RequireLocal,
	v1.Node_GetStatus_FullMethodName:          RequireLocal,
	v1.WebRTC_StartDataChannel_FullMethodName: AllowNonLeader,
}

// HasPreferLeaderMeta returns true if the context has the Prefer-Leader header set to true.
func HasPreferLeaderMeta(ctx context.Context) bool {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return false
	}
	leaderPref := md.Get(PreferLeaderMeta)
	return len(leaderPref) > 0 && leaderPref[0] == "true"
}
