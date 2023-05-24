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

	"github.com/spf13/cobra"
	v1 "gitlab.com/webmesh/api/v1"
	"google.golang.org/protobuf/proto"
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
	ValidArgsFunction: completeNodes,
	RunE: func(cmd *cobra.Command, args []string) error {
		client, closer, err := cliConfig.NewMeshClient()
		if err != nil {
			return err
		}
		defer closer.Close()
		var resp proto.Message
		if len(args) == 1 {
			resp, err = client.GetNode(context.Background(), &v1.GetNodeRequest{
				Id: args[0],
			})
		} else {
			resp, err = client.ListNodes(context.Background(), &emptypb.Empty{})
		}
		if err != nil {
			return err
		}
		return encodeToStdout(cmd, resp)
	},
}
