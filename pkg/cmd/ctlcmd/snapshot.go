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
	"io"
	"os"

	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/cobra"
	v1 "github.com/webmeshproj/api/v1"
)

var (
	snapshotOutput string
)

func init() {
	fl := snapshotCmd.Flags()
	fl.StringVar(&snapshotOutput, "output", "", "Output file (default: stdout)")
	rootCmd.AddCommand(snapshotCmd)
}

var snapshotCmd = &cobra.Command{
	Use:   "snapshot",
	Short: "Take a snapshot of the current state of the mesh",
	RunE: func(cmd *cobra.Command, args []string) error {
		var out io.Writer
		if snapshotOutput == "" || snapshotOutput == "-" {
			out = cmd.OutOrStdout()
		} else {
			f, err := os.Create(snapshotOutput)
			if err != nil {
				return err
			}
			defer f.Close()
			out = f
		}
		client, closer, err := cliConfig.NewNodeClient()
		if err != nil {
			return err
		}
		defer closer.Close()
		resp, err := client.Snapshot(cmd.Context(), &v1.SnapshotRequest{})
		if err != nil {
			return err
		}
		rawSnapshot := resp.GetSnapshot()
		_, err = out.Write(rawSnapshot)
		return err
	},
}
