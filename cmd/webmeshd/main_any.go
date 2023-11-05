//go:build !windows

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

package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/pflag"

	"github.com/webmeshproj/webmesh/pkg/cmd/daemoncmd"
	"github.com/webmeshproj/webmesh/pkg/version"
)

func run() {
	flagset := pflag.NewFlagSet("webmeshd", pflag.ContinueOnError)
	versionFlag := flagset.Bool("version", false, "Print version information and exit")
	versionJSONFlag := flagset.Bool("json", false, "Print version information in JSON format")
	config := daemoncmd.NewDefaultConfig().BindFlags("daemon.", flagset)
	err := flagset.Parse(os.Args[1:])
	if err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "Error parsing flags:", err)
		os.Exit(1)
	}
	version := version.GetBuildInfo()
	if *versionFlag || len(os.Args) > 1 && os.Args[1] == "version" {
		if *versionJSONFlag {
			fmt.Println(version.PrettyJSON("webmesh-node"))
			return
		}
		fmt.Println("Webmesh Daemon")
		fmt.Println("    Version:    ", version.Version)
		fmt.Println("    Git Commit: ", version.GitCommit)
		fmt.Println("    Build Date: ", version.BuildDate)
		return
	}
	if err := daemoncmd.Run(context.Background(), *config); err != nil {
		fmt.Fprintf(os.Stderr, "Error running daemon: %v\n", err)
		os.Exit(1)
	}
}
