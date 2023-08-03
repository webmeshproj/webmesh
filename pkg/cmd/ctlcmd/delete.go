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
	"github.com/spf13/cobra"
	v1 "github.com/webmeshproj/api/v1"
)

var (
	deleteEdgeFrom string
	deleteEdgeTo   string
)

func init() {
	deleteCmd.AddCommand(deleteRolesCmd)
	deleteCmd.AddCommand(deleteRoleBindingsCmd)
	deleteCmd.AddCommand(deleteGroupsCmd)
	deleteCmd.AddCommand(deleteNetworkACLsCmd)
	deleteCmd.AddCommand(deleteRoutesCmd)

	deleteEdgesCmd.Flags().StringVar(&getEdgeFrom, "from", "", "The source node ID")
	deleteEdgesCmd.Flags().StringVar(&getEdgeTo, "to", "", "The destination node ID")
	cobra.CheckErr(deleteEdgesCmd.RegisterFlagCompletionFunc("from", completeNodes(1)))
	cobra.CheckErr(deleteEdgesCmd.RegisterFlagCompletionFunc("to", completeNodes(1)))
	cobra.CheckErr(deleteEdgesCmd.MarkFlagRequired("from"))
	cobra.CheckErr(deleteEdgesCmd.MarkFlagRequired("to"))
	deleteCmd.AddCommand(deleteEdgesCmd)

	rootCmd.AddCommand(deleteCmd)
}

var deleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete resources from the mesh",
}

var deleteRolesCmd = &cobra.Command{
	Use:               "roles",
	Short:             "Delete roles from the mesh",
	Aliases:           []string{"role"},
	Args:              cobra.MinimumNArgs(1),
	ValidArgsFunction: completeRoles(-1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, closer, err := cliConfig.NewAdminClient()
		if err != nil {
			return err
		}
		defer closer.Close()
		for _, arg := range args {
			_, err = client.DeleteRole(cmd.Context(), &v1.Role{Name: arg})
			if err != nil {
				return err
			}
			cmd.Println("Deleted role", arg)
		}
		return nil
	},
}

var deleteRoleBindingsCmd = &cobra.Command{
	Use:               "rolebindings",
	Short:             "Delete rolebindings from the mesh",
	Aliases:           []string{"rolebinding", "rb"},
	Args:              cobra.MinimumNArgs(1),
	ValidArgsFunction: completeRoleBindings(-1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, closer, err := cliConfig.NewAdminClient()
		if err != nil {
			return err
		}
		defer closer.Close()
		for _, arg := range args {
			_, err = client.DeleteRoleBinding(cmd.Context(), &v1.RoleBinding{Name: arg})
			if err != nil {
				return err
			}
			cmd.Println("Deleted rolebinding", arg)
		}
		return nil
	},
}

var deleteGroupsCmd = &cobra.Command{
	Use:               "groups",
	Short:             "Delete groups from the mesh",
	Aliases:           []string{"group"},
	Args:              cobra.MinimumNArgs(1),
	ValidArgsFunction: completeGroups(-1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, closer, err := cliConfig.NewAdminClient()
		if err != nil {
			return err
		}
		defer closer.Close()
		for _, arg := range args {
			_, err = client.DeleteGroup(cmd.Context(), &v1.Group{Name: arg})
			if err != nil {
				return err
			}
			cmd.Println("Deleted group", arg)
		}
		return nil
	},
}

var deleteNetworkACLsCmd = &cobra.Command{
	Use:               "networkacls",
	Short:             "Delete networkacls from the mesh",
	Aliases:           []string{"networkacl", "nacl", "nacls", "acl", "acls"},
	Args:              cobra.MinimumNArgs(1),
	ValidArgsFunction: completeNetworkACLs(-1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, closer, err := cliConfig.NewAdminClient()
		if err != nil {
			return err
		}
		defer closer.Close()
		for _, arg := range args {
			_, err = client.DeleteNetworkACL(cmd.Context(), &v1.NetworkACL{Name: arg})
			if err != nil {
				return err
			}
			cmd.Println("Deleted networkacl", arg)
		}
		return nil
	},
}

var deleteRoutesCmd = &cobra.Command{
	Use:               "routes",
	Short:             "Delete routes from the mesh",
	Aliases:           []string{"route", "rt"},
	Args:              cobra.MinimumNArgs(1),
	ValidArgsFunction: completeRoutes(-1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, closer, err := cliConfig.NewAdminClient()
		if err != nil {
			return err
		}
		defer closer.Close()
		for _, arg := range args {
			_, err = client.DeleteRoute(cmd.Context(), &v1.Route{Name: arg})
			if err != nil {
				return err
			}
			cmd.Println("Deleted route", arg)
		}
		return nil
	},
}

var deleteEdgesCmd = &cobra.Command{
	Use:     "edges",
	Short:   "Delete edges from the mesh",
	Aliases: []string{"edge"},
	RunE: func(cmd *cobra.Command, _ []string) error {
		client, closer, err := cliConfig.NewAdminClient()
		if err != nil {
			return err
		}
		defer closer.Close()
		_, err = client.DeleteEdge(cmd.Context(), &v1.MeshEdge{
			Source: deleteEdgeFrom,
			Target: deleteEdgeTo,
		})
		return err
	},
}
