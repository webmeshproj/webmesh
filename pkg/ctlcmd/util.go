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
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

func encodeToStdout(cmd *cobra.Command, resp proto.Message) error {
	out, err := encoder.Marshal(resp)
	if err != nil {
		return err
	}
	cmd.Println(string(out))
	return nil
}

func completeNodes(maxNodes int) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) >= maxNodes {
			return nil, cobra.ShellCompDirectiveNoFileComp
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
