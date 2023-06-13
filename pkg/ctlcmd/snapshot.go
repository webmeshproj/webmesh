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
	"bytes"
	"database/sql"
	"fmt"
	"io"
	"os"

	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/cobra"
	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/node/pkg/meshdb/snapshots"
)

var (
	snapshotOutput string
	snapshotFormat string
)

func init() {
	fl := snapshotCmd.Flags()
	fl.StringVar(&snapshotOutput, "output", "", "Output file (default: stdout)")
	fl.StringVar(&snapshotFormat, "format", "raw", "Output format (raw|sqlite)")
	cobra.CheckErr(snapshotCmd.RegisterFlagCompletionFunc("format", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"raw", "sqlite"}, cobra.ShellCompDirectiveNoFileComp
	}))

	rootCmd.AddCommand(snapshotCmd)
}

var snapshotCmd = &cobra.Command{
	Use:   "snapshot",
	Short: "Take a snapshot of the current state of the mesh",
	RunE: func(cmd *cobra.Command, args []string) error {
		var out io.Writer
		if snapshotFormat == "sqlite" && snapshotOutput == "" {
			return fmt.Errorf("sqlite snapshot format requires --output")
		}
		if snapshotOutput == "" || snapshotOutput == "-" {
			out = cmd.OutOrStdout()
		} else if snapshotFormat == "raw" {
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

		switch snapshotFormat {
		case "raw":
			_, err = out.Write(rawSnapshot)
			return err
		case "sqlite":
			db, err := sql.Open("sqlite3", snapshotOutput)
			if err != nil {
				return err
			}
			defer db.Close()
			snapshotter := snapshots.New(db)
			err = snapshotter.Restore(cmd.Context(), io.NopCloser(bytes.NewReader(rawSnapshot)))
			return err
		default:
			return fmt.Errorf("unknown snapshot format %q", snapshotFormat)
		}
	},
}
