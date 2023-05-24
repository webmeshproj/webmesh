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

package mesh

import (
	"github.com/hashicorp/raft"
	v1 "gitlab.com/webmesh/api/v1"
	"google.golang.org/protobuf/types/known/timestamppb"

	"gitlab.com/webmesh/node/pkg/meshdb/peers"
)

func dbNodeToAPINode(node *peers.Node, leader raft.ServerID, servers []raft.Server) *v1.MeshNode {
	return &v1.MeshNode{
		Id: node.ID,
		Endpoint: func() string {
			if node.Endpoint.IsValid() {
				return node.Endpoint.String()
			}
			return ""
		}(),
		PublicKey: func() string {
			if len(node.PublicKey) > 0 {
				return node.PublicKey.String()
			}
			return ""
		}(),
		PrivateIpv4: func() string {
			if node.PrivateIPv4.IsValid() {
				return node.PrivateIPv4.String()
			}
			return ""
		}(),
		PrivateIpv6: func() string {
			if node.NetworkIPv6.IsValid() {
				return node.NetworkIPv6.String()
			}
			return ""
		}(),
		ClusterStatus: func() v1.ClusterStatus {
			for _, srv := range servers {
				if string(srv.ID) == node.ID {
					if srv.ID == leader {
						return v1.ClusterStatus_CLUSTER_LEADER
					}
					switch srv.Suffrage {
					case raft.Voter:
						return v1.ClusterStatus_CLUSTER_VOTER
					case raft.Nonvoter:
						return v1.ClusterStatus_CLUSTER_NON_VOTER
					}
				}
			}
			return v1.ClusterStatus_CLUSTER_STATUS_UNKNOWN
		}(),
		UpdatedAt: timestamppb.New(node.UpdatedAt),
		CreatedAt: timestamppb.New(node.CreatedAt),
	}
}
