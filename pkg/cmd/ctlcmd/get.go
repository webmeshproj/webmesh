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

package ctlcmd

import (
	"fmt"

	"github.com/spf13/cobra"
	v1 "github.com/webmeshproj/api/go/v1"
	"google.golang.org/protobuf/types/known/emptypb"
)

var (
	getEdgeFrom string
	getEdgeTo   string
)

func init() {
	getCmd.AddCommand(getNodesCmd)
	getCmd.AddCommand(getGraphCmd)
	getCmd.AddCommand(getRolesCmd)
	getCmd.AddCommand(getRoleBindingsCmd)
	getCmd.AddCommand(getGroupsCmd)
	getCmd.AddCommand(getNetworkACLsCmd)
	getCmd.AddCommand(getRoutesCmd)

	getEdgesCmd.Flags().StringVar(&getEdgeFrom, "from", "", "The source node ID")
	getEdgesCmd.Flags().StringVar(&getEdgeTo, "to", "", "The destination node ID")
	cobra.CheckErr(getEdgesCmd.RegisterFlagCompletionFunc("from", completeNodes(1)))
	cobra.CheckErr(getEdgesCmd.RegisterFlagCompletionFunc("to", completeNodes(1)))
	getCmd.AddCommand(getEdgesCmd)

	rootCmd.AddCommand(getCmd)
}

var getCmd = &cobra.Command{
	Use:   "get",
	Short: "Get resources from the mesh",
}

var getNodesCmd = &cobra.Command{
	Use:               "nodes [NODE_ID]",
	Short:             "Get nodes from the mesh",
	Aliases:           []string{"node"},
	Args:              cobra.MaximumNArgs(1),
	ValidArgsFunction: completeNodes(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, closer, err := cliConfig.NewMeshClient()
		if err != nil {
			return err
		}
		defer closer.Close()
		if len(args) == 1 {
			resp, err := client.GetNode(cmd.Context(), &v1.GetNodeRequest{
				Id: args[0],
			})
			if err != nil {
				return err
			}
			return encodeToStdout(cmd, resp)
		}
		resp, err := client.ListNodes(cmd.Context(), &emptypb.Empty{})
		if err != nil {
			return err
		}
		return encodeListToStdout(cmd, resp.Nodes)
	},
}

var getGraphCmd = &cobra.Command{
	Use:   "graph",
	Short: "Get the mesh graph in DOT format",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		client, closer, err := cliConfig.NewMeshClient()
		if err != nil {
			return err
		}
		defer closer.Close()
		resp, err := client.GetMeshGraph(cmd.Context(), &emptypb.Empty{})
		if err != nil {
			return err
		}
		fmt.Println(resp.Dot)
		return nil
	},
}

var getRolesCmd = &cobra.Command{
	Use:               "roles",
	Short:             "Get roles from the mesh",
	Aliases:           []string{"role"},
	Args:              cobra.MaximumNArgs(1),
	ValidArgsFunction: completeRoles(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, closer, err := cliConfig.NewAdminClient()
		if err != nil {
			return err
		}
		defer closer.Close()
		if len(args) == 1 {
			resp, err := client.GetRole(cmd.Context(), &v1.Role{Name: args[0]})
			if err != nil {
				return err
			}
			return encodeToStdout(cmd, resp)
		}
		resp, err := client.ListRoles(cmd.Context(), &emptypb.Empty{})
		if err != nil {
			return err
		}
		return encodeListToStdout(cmd, resp.Items)
	},
}

var getRoleBindingsCmd = &cobra.Command{
	Use:               "rolebindings",
	Short:             "Get rolebindings from the mesh",
	Aliases:           []string{"rolebinding", "rb"},
	Args:              cobra.MaximumNArgs(1),
	ValidArgsFunction: completeRoleBindings(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, closer, err := cliConfig.NewAdminClient()
		if err != nil {
			return err
		}
		defer closer.Close()
		if len(args) == 1 {
			resp, err := client.GetRoleBinding(cmd.Context(), &v1.RoleBinding{Name: args[0]})
			if err != nil {
				return err
			}
			return encodeToStdout(cmd, resp)
		}
		resp, err := client.ListRoleBindings(cmd.Context(), &emptypb.Empty{})
		if err != nil {
			return err
		}
		return encodeListToStdout(cmd, resp.Items)
	},
}

var getGroupsCmd = &cobra.Command{
	Use:               "groups",
	Short:             "Get groups from the mesh",
	Aliases:           []string{"group"},
	Args:              cobra.MaximumNArgs(1),
	ValidArgsFunction: completeGroups(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, closer, err := cliConfig.NewAdminClient()
		if err != nil {
			return err
		}
		defer closer.Close()
		if len(args) == 1 {
			resp, err := client.GetGroup(cmd.Context(), &v1.Group{Name: args[0]})
			if err != nil {
				return err
			}
			return encodeToStdout(cmd, resp)
		}
		resp, err := client.ListGroups(cmd.Context(), &emptypb.Empty{})
		if err != nil {
			return err
		}
		return encodeListToStdout(cmd, resp.Items)
	},
}

var getNetworkACLsCmd = &cobra.Command{
	Use:               "networkacls",
	Short:             "Get network ACLs from the mesh",
	Aliases:           []string{"networkacl", "nacl", "nacls", "acl", "acls"},
	Args:              cobra.MaximumNArgs(1),
	ValidArgsFunction: completeNetworkACLs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, closer, err := cliConfig.NewAdminClient()
		if err != nil {
			return err
		}
		defer closer.Close()
		if len(args) == 1 {
			resp, err := client.GetNetworkACL(cmd.Context(), &v1.NetworkACL{Name: args[0]})
			if err != nil {
				return err
			}
			return encodeToStdout(cmd, resp)
		}
		resp, err := client.ListNetworkACLs(cmd.Context(), &emptypb.Empty{})
		if err != nil {
			return err
		}
		return encodeListToStdout(cmd, resp.Items)
	},
}

var getRoutesCmd = &cobra.Command{
	Use:               "routes",
	Short:             "Get routes from the mesh",
	Aliases:           []string{"route", "rt"},
	Args:              cobra.MaximumNArgs(1),
	ValidArgsFunction: completeRoutes(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, closer, err := cliConfig.NewAdminClient()
		if err != nil {
			return err
		}
		defer closer.Close()
		if len(args) == 1 {
			resp, err := client.GetRoute(cmd.Context(), &v1.Route{Name: args[0]})
			if err != nil {
				return err
			}
			return encodeToStdout(cmd, resp)
		}
		resp, err := client.ListRoutes(cmd.Context(), &emptypb.Empty{})
		if err != nil {
			return err
		}
		return encodeListToStdout(cmd, resp.Items)
	},
}

var getEdgesCmd = &cobra.Command{
	Use:     "edges",
	Short:   "Get edges from the mesh",
	Aliases: []string{"edge"},
	RunE: func(cmd *cobra.Command, _ []string) error {
		client, closer, err := cliConfig.NewAdminClient()
		if err != nil {
			return err
		}
		defer closer.Close()
		if getEdgeFrom != "" && getEdgeTo != "" {
			resp, err := client.GetEdge(cmd.Context(), &v1.MeshEdge{
				Source: getEdgeFrom,
				Target: getEdgeTo,
			})
			if err != nil {
				return err
			}
			return encodeToStdout(cmd, resp)
		}
		resp, err := client.ListEdges(cmd.Context(), &emptypb.Empty{})
		if err != nil {
			return err
		}
		// Filter the list if the user has specified a source or target
		if getEdgeFrom != "" || getEdgeTo != "" {
			filtered := make([]*v1.MeshEdge, 0)
			for _, edge := range resp.Items {
				if getEdgeFrom != "" && getEdgeFrom != edge.Source {
					continue
				}
				if getEdgeTo != "" && getEdgeTo != edge.Target {
					continue
				}
				filtered = append(filtered, edge)
			}
			resp.Items = filtered
		}
		return encodeListToStdout(cmd, resp.Items)
	},
}
