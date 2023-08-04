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

package leaderproxy

import (
	v1 "github.com/webmeshproj/api/v1"
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
	// Node API
	v1.Node_Join_FullMethodName:                 RequireLeader,
	v1.Node_Update_FullMethodName:               RequireLeader,
	v1.Node_Leave_FullMethodName:                RequireLeader,
	v1.Node_GetStatus_FullMethodName:            RequireLocal,
	v1.Node_Snapshot_FullMethodName:             AllowNonLeader,
	v1.Node_NegotiateDataChannel_FullMethodName: RequireLocal,

	// Mesh API
	v1.Mesh_GetNode_FullMethodName:      AllowNonLeader,
	v1.Mesh_ListNodes_FullMethodName:    AllowNonLeader,
	v1.Mesh_GetMeshGraph_FullMethodName: AllowNonLeader,

	// Peer Discovery API
	v1.PeerDiscovery_ListPeers_FullMethodName: AllowNonLeader,

	// WebRTC API
	v1.WebRTC_StartDataChannel_FullMethodName: AllowNonLeader,

	// Admin API
	v1.Admin_PutRole_FullMethodName:    RequireLeader,
	v1.Admin_DeleteRole_FullMethodName: RequireLeader,
	v1.Admin_GetRole_FullMethodName:    AllowNonLeader,
	v1.Admin_ListRoles_FullMethodName:  AllowNonLeader,

	v1.Admin_PutRoleBinding_FullMethodName:    RequireLeader,
	v1.Admin_DeleteRoleBinding_FullMethodName: RequireLeader,
	v1.Admin_GetRoleBinding_FullMethodName:    AllowNonLeader,
	v1.Admin_ListRoleBindings_FullMethodName:  AllowNonLeader,

	v1.Admin_PutGroup_FullMethodName:    RequireLeader,
	v1.Admin_DeleteGroup_FullMethodName: RequireLeader,
	v1.Admin_GetGroup_FullMethodName:    AllowNonLeader,
	v1.Admin_ListGroups_FullMethodName:  AllowNonLeader,

	v1.Admin_PutNetworkACL_FullMethodName:    RequireLeader,
	v1.Admin_DeleteNetworkACL_FullMethodName: RequireLeader,
	v1.Admin_GetNetworkACL_FullMethodName:    AllowNonLeader,
	v1.Admin_ListNetworkACLs_FullMethodName:  AllowNonLeader,

	v1.Admin_PutRoute_FullMethodName:    RequireLeader,
	v1.Admin_DeleteRoute_FullMethodName: RequireLeader,
	v1.Admin_GetRoute_FullMethodName:    AllowNonLeader,
	v1.Admin_ListRoutes_FullMethodName:  AllowNonLeader,

	v1.Admin_PutEdge_FullMethodName:    RequireLeader,
	v1.Admin_DeleteEdge_FullMethodName: RequireLeader,
	v1.Admin_GetEdge_FullMethodName:    AllowNonLeader,
	v1.Admin_ListEdges_FullMethodName:  AllowNonLeader,
}
