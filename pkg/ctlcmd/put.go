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
)

func init() {
	putRoleFlags := putRoleCmd.Flags()
	putRoleFlags.StringArrayVar(&putRoleVerbs, "verb", nil, "verbs to add to the role")
	putRoleFlags.StringArrayVar(&putRoleResources, "resource", nil, "resources to add to the role")
	putRoleFlags.StringArrayVar(&putRoleResourceNames, "resource-name", nil, "resource names to add to the role")

	cobra.CheckErr(putRoleCmd.MarkFlagRequired("verb"))
	cobra.CheckErr(putRoleCmd.MarkFlagRequired("resource"))

	cobra.CheckErr(putRoleCmd.RegisterFlagCompletionFunc("verb", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"put", "get", "delete", "*"}, cobra.ShellCompDirectiveNoFileComp
	}))
	cobra.CheckErr(putRoleCmd.RegisterFlagCompletionFunc("resource", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"votes", "roles", "rolebindings", "groups", "networkacls", "*"}, cobra.ShellCompDirectiveNoFileComp
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

	putCmd.AddCommand(putRoleCmd)
	putCmd.AddCommand(putRoleBindingCmd)
	putCmd.AddCommand(putGroupCmd)

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
							case "*":
								resources[i] = v1.RuleResource_RESOURCE_ALL
							}
						}
						return resources
					}(),
					Verbs: func() []v1.RuleVerbs {
						verbs := make([]v1.RuleVerbs, len(putRoleVerbs))
						for i, verb := range putRoleVerbs {
							switch verb {
							case "put":
								verbs[i] = v1.RuleVerbs_VERB_PUT
							case "get":
								verbs[i] = v1.RuleVerbs_VERB_GET
							case "delete":
								verbs[i] = v1.RuleVerbs_VERB_DELETE
							case "*":
								verbs[i] = v1.RuleVerbs_VERB_ALL
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
