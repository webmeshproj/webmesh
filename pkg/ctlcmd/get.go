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

package ctlcmd

import (
	"context"
	"encoding/json"

	"github.com/spf13/cobra"
	v1 "gitlab.com/webmesh/api/v1"
	"google.golang.org/protobuf/types/known/emptypb"
)

func init() {
	getCmd.AddCommand(getNodesCmd)
	rootCmd.AddCommand(getCmd)
}

var getCmd = &cobra.Command{
	Use:   "get",
	Short: "Get resources from the cluster",
}

var getNodesCmd = &cobra.Command{
	Use:               "nodes [NODE_ID]",
	Short:             "Get nodes from the mesh",
	Aliases:           []string{"node"},
	Args:              cobra.MaximumNArgs(1),
	PreRunE:           initClient,
	PostRun:           closeClient,
	ValidArgsFunction: completeNodes,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 1 {
			node, err := client.GetNode(context.Background(), &v1.GetNodeRequest{
				Id: args[0],
			})
			if err != nil {
				return err
			}
			return outNodeJSON(cmd, node)
		}
		nodes, err := client.ListNodes(context.Background(), &emptypb.Empty{})
		if err != nil {
			return err
		}
		return outNodeListJSON(cmd, nodes.Nodes)
	},
}

func outNodeListJSON(cmd *cobra.Command, v []*v1.MeshNode) error {
	out, err := json.MarshalIndent(toNodeList(v), "", "  ")
	if err != nil {
		return err
	}
	cmd.Println(string(out))
	return nil
}

func outNodeJSON(cmd *cobra.Command, v *v1.MeshNode) error {
	out, err := json.MarshalIndent(toNode(v), "", "  ")
	if err != nil {
		return err
	}
	cmd.Println(string(out))
	return nil
}

func toNodeList(nodes []*v1.MeshNode) []map[string]any {
	out := make([]map[string]any, len(nodes))
	for i, node := range nodes {
		n := toNode(node)
		out[i] = n
	}
	return out
}

func toNode(node *v1.MeshNode) map[string]any {
	return map[string]any{
		"id":              node.GetId(),
		"endpoint":        node.GetEndpoint(),
		"public_key":      node.GetPublicKey(),
		"asn":             node.GetAsn(),
		"private_ipv4":    node.GetPrivateIpv4(),
		"private_ipv6":    node.GetPrivateIpv6(),
		"available_zones": node.GetAvailableZones(),
		"allowed_ips":     node.GetAllowedIps(),
		"created_at":      node.GetCreatedAt().AsTime(),
		"updated_at":      node.GetUpdatedAt().AsTime(),
		"status":          node.GetStatus().String(),
	}
}
