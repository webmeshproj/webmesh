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
	"time"

	"github.com/spf13/cobra"
	v1 "gitlab.com/webmesh/api/v1"
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
		return outStatusJSON(cmd, status)
	},
}

func outStatusJSON(cmd *cobra.Command, status *v1.Status) error {
	out, err := json.MarshalIndent(map[string]any{
		"version":    status.GetVersion(),
		"commit":     status.GetCommit(),
		"build_date": status.GetBuildDate(),
		"uptime":     status.GetUptime(),
		"started_at": status.GetStartedAt().AsTime().Format(time.RFC3339),
		"features": func() []string {
			var features []string
			for _, feature := range status.GetFeatures() {
				features = append(features, feature.String())
			}
			return features
		}(),
		"peers":          status.Peers,
		"status":         status.Status.String(),
		"current_leader": status.CurrentLeader,
	}, "", "  ")
	if err != nil {
		return err
	}
	cmd.Println(string(out))
	return nil
}
