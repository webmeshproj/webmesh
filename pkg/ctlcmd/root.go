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

// Package ctlcmd contains the wmctl CLI tool.
package ctlcmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/webmeshproj/node/pkg/ctlcmd/config"
)

var (
	configFileFlag string
	cliConfig      *config.Config
)

func init() {
	cliConfig = config.New()
	cliConfigPath := config.DefaultConfigPath
	if configPath := os.Getenv("WMCTL_CONFIG"); configPath != "" {
		cliConfigPath = configPath
	}
	if err := cliConfig.LoadFile(cliConfigPath); err != nil {
		if !os.IsNotExist(err) && cliConfigPath != config.DefaultConfigPath {
			fmt.Fprintf(os.Stderr, "Error loading CLI config: %v\n", err)
			os.Exit(1)
		}
	}
	cliConfig.BindFlags(rootCmd.PersistentFlags())
	rootCmd.PersistentFlags().StringVarP(&configFileFlag, "config", "c", "", "Path to the CLI configuration file")
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()

}

var rootCmd = &cobra.Command{
	Use:           "wmctl",
	Short:         "wmctl is a CLI tool for managing a webmesh",
	SilenceErrors: true,
	SilenceUsage:  true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if configFileFlag != "" {
			if err := cliConfig.LoadFile(configFileFlag); err != nil {
				return fmt.Errorf("failed to load CLI config: %w", err)
			}
		}
		return nil
	},
}
