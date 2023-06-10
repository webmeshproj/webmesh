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
	"strings"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

var (
	encoder = protojson.MarshalOptions{
		Multiline: true,
		Indent:    "  ",
	}
)

func encodeToStdout(cmd *cobra.Command, resp proto.Message) error {
	out, err := encoder.Marshal(resp)
	if err != nil {
		return err
	}
	cmd.Println(string(out))
	return nil
}

func encodeListToStdout[T proto.Message](cmd *cobra.Command, resp []T) error {
	var out strings.Builder
	out.WriteString("[\n")
	for i, msg := range resp {
		if i > 0 {
			out.WriteString(",\n")
		}
		encoded, err := encoder.Marshal(proto.Message(msg))
		if err != nil {
			return err
		}
		// Include the indent in the output
		out.WriteString("  ")
		spl := strings.Split(string(encoded), "\n")
		for i, line := range spl {
			out.WriteString(line)
			if i < len(spl)-1 {
				out.WriteString("\n  ")
			}
		}
	}
	out.WriteString("\n]")
	cmd.Println(out.String())
	return nil
}

func completeNodes(maxNodes int) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if maxNodes > 0 && len(args) >= maxNodes {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		if configFileFlag != "" {
			if err := cliConfig.LoadFile(configFileFlag); err != nil {
				return nil, cobra.ShellCompDirectiveError
			}
		}
		client, closer, err := cliConfig.NewMeshClient()
		if err != nil {
			return nil, cobra.ShellCompDirectiveError
		}
		defer closer.Close()
		resp, err := client.ListNodes(cmd.Context(), &emptypb.Empty{})
		if err != nil {
			return nil, cobra.ShellCompDirectiveError
		}
		var names []string
		for _, node := range resp.Nodes {
			names = append(names, node.GetId())
		}
		return names, cobra.ShellCompDirectiveNoFileComp
	}
}

func completeRoles(maxRoles int) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if maxRoles > 0 && len(args) >= maxRoles {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		if configFileFlag != "" {
			if err := cliConfig.LoadFile(configFileFlag); err != nil {
				return nil, cobra.ShellCompDirectiveError
			}
		}
		client, closer, err := cliConfig.NewAdminClient()
		if err != nil {
			return nil, cobra.ShellCompDirectiveError
		}
		defer closer.Close()
		resp, err := client.ListRoles(cmd.Context(), &emptypb.Empty{})
		if err != nil {
			return nil, cobra.ShellCompDirectiveError
		}
		var names []string
		for _, role := range resp.Items {
			names = append(names, role.GetName())
		}
		return names, cobra.ShellCompDirectiveNoFileComp
	}
}

func completeRoleBindings(maxRoleBindings int) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if maxRoleBindings > 0 && len(args) >= maxRoleBindings {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		if configFileFlag != "" {
			if err := cliConfig.LoadFile(configFileFlag); err != nil {
				return nil, cobra.ShellCompDirectiveError
			}
		}
		client, closer, err := cliConfig.NewAdminClient()
		if err != nil {
			return nil, cobra.ShellCompDirectiveError
		}
		defer closer.Close()
		resp, err := client.ListRoleBindings(cmd.Context(), &emptypb.Empty{})
		if err != nil {
			return nil, cobra.ShellCompDirectiveError
		}
		var names []string
		for _, rb := range resp.Items {
			names = append(names, rb.GetName())
		}
		return names, cobra.ShellCompDirectiveNoFileComp
	}
}

func completeGroups(maxGroups int) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if maxGroups > 0 && len(args) >= maxGroups {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		if configFileFlag != "" {
			if err := cliConfig.LoadFile(configFileFlag); err != nil {
				return nil, cobra.ShellCompDirectiveError
			}
		}
		client, closer, err := cliConfig.NewAdminClient()
		if err != nil {
			return nil, cobra.ShellCompDirectiveError
		}
		defer closer.Close()
		resp, err := client.ListGroups(cmd.Context(), &emptypb.Empty{})
		if err != nil {
			return nil, cobra.ShellCompDirectiveError
		}
		var names []string
		for _, group := range resp.Items {
			names = append(names, group.GetName())
		}
		return names, cobra.ShellCompDirectiveNoFileComp
	}
}

func completeNetworkACLs(maxACLs int) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if maxACLs > 0 && len(args) >= maxACLs {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		if configFileFlag != "" {
			if err := cliConfig.LoadFile(configFileFlag); err != nil {
				return nil, cobra.ShellCompDirectiveError
			}
		}
		client, closer, err := cliConfig.NewAdminClient()
		if err != nil {
			return nil, cobra.ShellCompDirectiveError
		}
		defer closer.Close()
		resp, err := client.ListNetworkACLs(cmd.Context(), &emptypb.Empty{})
		if err != nil {
			return nil, cobra.ShellCompDirectiveError
		}
		var names []string
		for _, acl := range resp.Items {
			names = append(names, acl.GetName())
		}
		return names, cobra.ShellCompDirectiveNoFileComp
	}
}

func completeRoutes(maxRoutes int) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if maxRoutes > 0 && len(args) >= maxRoutes {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		if configFileFlag != "" {
			if err := cliConfig.LoadFile(configFileFlag); err != nil {
				return nil, cobra.ShellCompDirectiveError
			}
		}
		client, closer, err := cliConfig.NewAdminClient()
		if err != nil {
			return nil, cobra.ShellCompDirectiveError
		}
		defer closer.Close()
		resp, err := client.ListRoutes(cmd.Context(), &emptypb.Empty{})
		if err != nil {
			return nil, cobra.ShellCompDirectiveError
		}
		var names []string
		for _, route := range resp.Items {
			names = append(names, route.GetName())
		}
		return names, cobra.ShellCompDirectiveNoFileComp
	}
}
