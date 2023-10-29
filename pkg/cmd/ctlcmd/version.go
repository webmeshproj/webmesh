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
	"github.com/spf13/cobra"

	"github.com/webmeshproj/webmesh/pkg/version"
)

var (
	versionJSON bool
)

func init() {
	versionCmd.Flags().BoolVar(&versionJSON, "json", false, "Print version information in JSON format")
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of the CLI",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		version := version.GetBuildInfo()
		if versionJSON {
			cmd.Println(version.PrettyJSON("webmesh-cli"))
			return nil
		}
		cmd.Println("Webmesh CLI")
		cmd.Println("    Version:    ", version.Version)
		cmd.Println("    Git Commit: ", version.GitCommit)
		cmd.Println("    Build Date: ", version.BuildDate)
		return nil
	},
}
