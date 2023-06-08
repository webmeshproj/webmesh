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
	v1 "github.com/webmeshproj/api/v1"
)

func init() {
	rootCmd.AddCommand(statusCmd)
}

var statusCmd = &cobra.Command{
	Use:               "status [NODE_ID]",
	Short:             "Retrieves the status of a node in the cluster",
	Args:              cobra.MaximumNArgs(1),
	ValidArgsFunction: completeNodes(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, closer, err := cliConfig.NewNodeClient()
		if err != nil {
			return err
		}
		defer closer.Close()
		var req v1.GetStatusRequest
		if len(args) > 0 {
			req.Id = args[0]
		}
		status, err := client.GetStatus(cmd.Context(), &req)
		if err != nil {
			return err
		}
		return encodeToStdout(cmd, status)
	},
}
