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
	"google.golang.org/protobuf/types/known/emptypb"
)

func init() {
	rootCmd.AddCommand(statusCmd)
}

var statusCmd = &cobra.Command{
	Use:     "status",
	Short:   "Retrieves the status of a node in the cluster",
	PreRunE: initClient,
	PostRun: closeClient,
	RunE: func(cmd *cobra.Command, args []string) error {
		status, err := client.GetStatus(context.Background(), &emptypb.Empty{})
		if err != nil {
			return err
		}
		return encodeToStdout(cmd, status)
	},
}
