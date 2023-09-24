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
	"errors"

	"github.com/spf13/cobra"
	v1 "github.com/webmeshproj/api/v1"
)

var (
	putRoleVerbs         []string
	putRoleResources     []string
	putRoleResourceNames []string

	putRoleBindingRole   string
	putRoleBindingNodes  []string
	putRoleBindingUsers  []string
	putRoleBindingGroups []string

	putGroupNodes []string
	putGroupUsers []string

	putNetworkACLPriority int32
	putNetworkACLSrcNodes []string
	putNetworkACLDstNodes []string
	putNetworkACLSrcCIDRs []string
	putNetworkACLDstCIDRs []string
	putNetworkACLAccept   bool
	putNetworkACLDeny     bool

	putRouteNode    string
	putRouteCIDRs   []string
	putRouteNextHop string

	putEdgeFrom   string
	putEdgeTo     string
	putEdgeWeight int32
	putEdgeICE    bool
	putEdgeLibp2p bool
)

func init() {
	putRoleFlags := putRoleCmd.Flags()
	putRoleFlags.StringArrayVar(&putRoleVerbs, "verb", nil, "verbs to add to the role")
	putRoleFlags.StringArrayVar(&putRoleResources, "resource", nil, "resources to add to the role")
	putRoleFlags.StringArrayVar(&putRoleResourceNames, "resource-name", nil, "resource names to add to the role")
	cobra.CheckErr(putRoleCmd.MarkFlagRequired("verb"))
	cobra.CheckErr(putRoleCmd.MarkFlagRequired("resource"))
	cobra.CheckErr(putRoleCmd.RegisterFlagCompletionFunc("verb", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"get", "put", "delete", "*"}, cobra.ShellCompDirectiveNoFileComp
	}))
	cobra.CheckErr(putRoleCmd.RegisterFlagCompletionFunc("resource", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"votes", "roles", "rolebindings", "groups", "networkacls", "datachannels", "pubsub", "observers", "routes", "edges", "*"}, cobra.ShellCompDirectiveNoFileComp
	}))

	putRoleBindingFlags := putRoleBindingCmd.Flags()
	putRoleBindingFlags.StringVar(&putRoleBindingRole, "role", "", "role to bind")
	putRoleBindingFlags.StringArrayVar(&putRoleBindingNodes, "node", nil, "nodes to bind the role to")
	putRoleBindingFlags.StringArrayVar(&putRoleBindingUsers, "user", nil, "users to bind the role to")
	putRoleBindingFlags.StringArrayVar(&putRoleBindingGroups, "group", nil, "groups to bind the role to")
	cobra.CheckErr(putRoleBindingCmd.MarkFlagRequired("role"))
	cobra.CheckErr(putRoleBindingCmd.RegisterFlagCompletionFunc("role", completeRoles(1)))

	putGroupFlags := putGroupCmd.Flags()
	putGroupFlags.StringArrayVar(&putGroupNodes, "node", nil, "nodes to add to the group")
	putGroupFlags.StringArrayVar(&putGroupUsers, "user", nil, "users to add to the group")

	putACLFlags := putNetworkACLCmd.Flags()
	putACLFlags.Int32Var(&putNetworkACLPriority, "priority", 0, "priority of the ACL")
	putACLFlags.StringArrayVar(&putNetworkACLSrcNodes, "src-node", nil, "source nodes to add to the ACL")
	putACLFlags.StringArrayVar(&putNetworkACLDstNodes, "dst-node", nil, "destination nodes to add to the ACL")
	putACLFlags.StringArrayVar(&putNetworkACLSrcCIDRs, "src-cidr", nil, "source CIDRs to add to the ACL")
	putACLFlags.StringArrayVar(&putNetworkACLDstCIDRs, "dst-cidr", nil, "destination CIDRs to add to the ACL")
	putACLFlags.BoolVar(&putNetworkACLAccept, "accept", true, "whether to accept traffic matching the ACL")
	putACLFlags.BoolVar(&putNetworkACLDeny, "deny", false, "whether to deny traffic matching the ACL")
	cobra.CheckErr(putNetworkACLCmd.RegisterFlagCompletionFunc("src-node", completeNodes(1)))
	cobra.CheckErr(putNetworkACLCmd.RegisterFlagCompletionFunc("dst-node", completeNodes(1)))

	putRouteFlags := putRouteCmd.Flags()
	putRouteFlags.StringVar(&putRouteNode, "node", "", "node to add the route to")
	putRouteFlags.StringArrayVar(&putRouteCIDRs, "cidr", nil, "CIDRs to add to the route")
	putRouteFlags.StringVar(&putRouteNextHop, "next-hop", "", "next hop to add to the route")
	cobra.CheckErr(putRouteCmd.MarkFlagRequired("node"))
	cobra.CheckErr(putRouteCmd.MarkFlagRequired("cidr"))
	cobra.CheckErr(putRouteCmd.RegisterFlagCompletionFunc("node", completeNodes(1)))
	cobra.CheckErr(putRouteCmd.RegisterFlagCompletionFunc("next-hop", completeNodes(1)))

	putEdgeFlags := putEdgeCmd.Flags()
	putEdgeFlags.StringVar(&putEdgeFrom, "from", "", "node to add the edge from")
	putEdgeFlags.StringVar(&putEdgeTo, "to", "", "node to add the edge to")
	putEdgeFlags.Int32Var(&putEdgeWeight, "weight", 1, "weight of the edge")
	putEdgeFlags.BoolVar(&putEdgeICE, "ice", false, "whether the edge is negotiated over ICE")
	putEdgeFlags.BoolVar(&putEdgeICE, "libp2p", false, "whether the edge is negotiated over libp2p")
	cobra.CheckErr(putEdgeCmd.RegisterFlagCompletionFunc("from", completeNodes(1)))
	cobra.CheckErr(putEdgeCmd.RegisterFlagCompletionFunc("to", completeNodes(1)))
	cobra.CheckErr(putEdgeCmd.MarkFlagRequired("from"))
	cobra.CheckErr(putEdgeCmd.MarkFlagRequired("to"))

	putCmd.AddCommand(putRoleCmd)
	putCmd.AddCommand(putRoleBindingCmd)
	putCmd.AddCommand(putGroupCmd)
	putCmd.AddCommand(putNetworkACLCmd)
	putCmd.AddCommand(putRouteCmd)
	putCmd.AddCommand(putEdgeCmd)

	rootCmd.AddCommand(putCmd)
}

var putCmd = &cobra.Command{
	Use:   "put",
	Short: "Create or update resources in the mesh",
}

var putRoleCmd = &cobra.Command{
	Use:               "roles [NAME]",
	Short:             "Create or update a role with a single rule in the mesh",
	Aliases:           []string{"role"},
	Args:              cobra.MaximumNArgs(1),
	ValidArgsFunction: completeRoles(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return errors.New("no role name specified")
		}
		role := &v1.Role{
			Name: args[0],
			Rules: []*v1.Rule{
				{
					Resources: func() []v1.RuleResource {
						resources := make([]v1.RuleResource, len(putRoleResources))
						for i, resource := range putRoleResources {
							switch resource {
							case "votes":
								resources[i] = v1.RuleResource_RESOURCE_VOTES
							case "roles":
								resources[i] = v1.RuleResource_RESOURCE_ROLES
							case "rolebindings":
								resources[i] = v1.RuleResource_RESOURCE_ROLE_BINDINGS
							case "groups":
								resources[i] = v1.RuleResource_RESOURCE_GROUPS
							case "networkacls":
								resources[i] = v1.RuleResource_RESOURCE_NETWORK_ACLS
							case "routes":
								resources[i] = v1.RuleResource_RESOURCE_ROUTES
							case "datachannels":
								resources[i] = v1.RuleResource_RESOURCE_DATA_CHANNELS
							case "pubsub":
								resources[i] = v1.RuleResource_RESOURCE_PUBSUB
							case "observers":
								resources[i] = v1.RuleResource_RESOURCE_OBSERVERS
							case "edges":
								resources[i] = v1.RuleResource_RESOURCE_EDGES
							case "*":
								resources[i] = v1.RuleResource_RESOURCE_ALL
							}
						}
						return resources
					}(),
					Verbs: func() []v1.RuleVerb {
						verbs := make([]v1.RuleVerb, len(putRoleVerbs))
						for i, verb := range putRoleVerbs {
							switch verb {
							case "get":
								verbs[i] = v1.RuleVerb_VERB_GET
							case "put":
								verbs[i] = v1.RuleVerb_VERB_PUT
							case "delete":
								verbs[i] = v1.RuleVerb_VERB_DELETE
							case "*":
								verbs[i] = v1.RuleVerb_VERB_ALL
							}
						}
						return verbs
					}(),
					ResourceNames: putRoleResourceNames,
				},
			},
		}
		client, closer, err := cliConfig.NewAdminClient()
		if err != nil {
			return err
		}
		defer closer.Close()
		_, err = client.PutRole(cmd.Context(), role)
		if err != nil {
			return err
		}
		cmd.Println("put role", role.Name)
		return nil
	},
}

var putRoleBindingCmd = &cobra.Command{
	Use:               "rolebindings [NAME]",
	Short:             "Create or update a rolebindings in the mesh",
	Aliases:           []string{"rolebinding", "rb"},
	Args:              cobra.MaximumNArgs(1),
	ValidArgsFunction: completeRoleBindings(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return errors.New("no rolebinding name specified")
		}
		if len(putRoleBindingNodes) == 0 && len(putRoleBindingUsers) == 0 && len(putRoleBindingGroups) == 0 {
			return errors.New("no nodes, users, or groups specified")
		}
		roleBinding := &v1.RoleBinding{
			Name: args[0],
			Role: putRoleBindingRole,
			Subjects: func() []*v1.Subject {
				subjects := make([]*v1.Subject, 0)
				for _, node := range putRoleBindingNodes {
					subjects = append(subjects, &v1.Subject{
						Type: v1.SubjectType_SUBJECT_NODE,
						Name: node,
					})
				}
				for _, user := range putRoleBindingUsers {
					subjects = append(subjects, &v1.Subject{
						Type: v1.SubjectType_SUBJECT_USER,
						Name: user,
					})
				}
				for _, group := range putRoleBindingGroups {
					subjects = append(subjects, &v1.Subject{
						Type: v1.SubjectType_SUBJECT_GROUP,
						Name: group,
					})
				}
				return subjects
			}(),
		}
		client, closer, err := cliConfig.NewAdminClient()
		if err != nil {
			return err
		}
		defer closer.Close()
		_, err = client.PutRoleBinding(cmd.Context(), roleBinding)
		if err != nil {
			return err
		}
		cmd.Println("put rolebinding", roleBinding.Name)
		return nil
	},
}

var putGroupCmd = &cobra.Command{
	Use:               "groups [NAME]",
	Short:             "Create or update a group in the mesh",
	Aliases:           []string{"group"},
	Args:              cobra.MaximumNArgs(1),
	ValidArgsFunction: completeGroups(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return errors.New("no group name specified")
		}
		if len(putGroupNodes) == 0 && len(putGroupUsers) == 0 {
			return errors.New("no nodes or users specified")
		}
		group := &v1.Group{
			Name: args[0],
			Subjects: func() []*v1.Subject {
				subjects := make([]*v1.Subject, 0)
				for _, node := range putGroupNodes {
					subjects = append(subjects, &v1.Subject{
						Type: v1.SubjectType_SUBJECT_NODE,
						Name: node,
					})
				}
				for _, user := range putGroupUsers {
					subjects = append(subjects, &v1.Subject{
						Type: v1.SubjectType_SUBJECT_USER,
						Name: user,
					})
				}
				return subjects
			}(),
		}
		client, closer, err := cliConfig.NewAdminClient()
		if err != nil {
			return err
		}
		defer closer.Close()
		_, err = client.PutGroup(cmd.Context(), group)
		if err != nil {
			return err
		}
		cmd.Println("put group", group.Name)
		return nil
	},
}

var putNetworkACLCmd = &cobra.Command{
	Use:               "networkacls [NAME]",
	Short:             "Create or update a networkacl in the mesh",
	Aliases:           []string{"networkacl", "nacl", "nacls", "acl", "acls"},
	Args:              cobra.MaximumNArgs(1),
	ValidArgsFunction: completeNetworkACLs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return errors.New("no networkacl name specified")
		}
		if len(putNetworkACLSrcNodes) == 0 && len(putNetworkACLDstNodes) == 0 && len(putNetworkACLSrcCIDRs) == 0 && len(putNetworkACLDstCIDRs) == 0 {
			return errors.New("no sources or targets specified")
		}
		action := func() v1.ACLAction {
			if putNetworkACLDeny {
				return v1.ACLAction_ACTION_DENY
			}
			if putNetworkACLAccept {
				return v1.ACLAction_ACTION_ACCEPT
			}
			return v1.ACLAction_ACTION_ACCEPT
		}()
		networkACL := &v1.NetworkACL{
			Name:             args[0],
			Priority:         putNetworkACLPriority,
			Action:           action,
			SourceNodes:      putNetworkACLSrcNodes,
			DestinationNodes: putNetworkACLDstNodes,
			SourceCidrs:      putNetworkACLSrcCIDRs,
			DestinationCidrs: putNetworkACLDstCIDRs,
		}
		client, closer, err := cliConfig.NewAdminClient()
		if err != nil {
			return err
		}
		defer closer.Close()
		_, err = client.PutNetworkACL(cmd.Context(), networkACL)
		if err != nil {
			return err
		}
		cmd.Println("put networkacl", networkACL.Name)
		return nil
	},
}

var putRouteCmd = &cobra.Command{
	Use:               "routes [NAME]",
	Short:             "Create or update a route in the mesh",
	Aliases:           []string{"route", "rt"},
	Args:              cobra.MaximumNArgs(1),
	ValidArgsFunction: completeRoutes(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return errors.New("no route name specified")
		}
		route := &v1.Route{
			Name:             args[0],
			Node:             putRouteNode,
			DestinationCidrs: putRouteCIDRs,
			NextHopNode:      putRouteNextHop,
		}
		client, closer, err := cliConfig.NewAdminClient()
		if err != nil {
			return err
		}
		defer closer.Close()
		_, err = client.PutRoute(cmd.Context(), route)
		if err != nil {
			return err
		}
		cmd.Println("put route", route.Name)
		return nil
	},
}

var putEdgeCmd = &cobra.Command{
	Use:     "edges [NAME]",
	Short:   "Create or update an edge in the mesh",
	Aliases: []string{"edge"},
	RunE: func(cmd *cobra.Command, _ []string) error {
		client, closer, err := cliConfig.NewAdminClient()
		if err != nil {
			return err
		}
		defer closer.Close()
		edge := &v1.MeshEdge{
			Source:     putEdgeFrom,
			Target:     putEdgeTo,
			Weight:     putEdgeWeight,
			Attributes: make(map[string]string),
		}
		if putEdgeICE {
			edge.Attributes[v1.EdgeAttribute_EDGE_ATTRIBUTE_ICE.String()] = "true"
		}
		if putEdgeLibp2p {
			edge.Attributes[v1.EdgeAttribute_EDGE_ATTRIBUTE_LIBP2P.String()] = "true"
		}
		_, err = client.PutEdge(cmd.Context(), edge)
		if err != nil {
			return err
		}
		cmd.Println("put edge from", edge.GetSource(), "to", edge.GetTarget())
		return nil
	},
}
