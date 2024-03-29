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

// Package nodecmd contains the entrypoint for webmesh nodes.
package nodecmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/pflag"

	"github.com/webmeshproj/webmesh/pkg/cmd/bridgecmd"
	"github.com/webmeshproj/webmesh/pkg/cmd/daemoncmd"
	"github.com/webmeshproj/webmesh/pkg/config"
	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/embed"
	"github.com/webmeshproj/webmesh/pkg/logging"
	"github.com/webmeshproj/webmesh/pkg/version"
)

var (
	flagset = pflag.NewFlagSet("webmesh-node", pflag.ContinueOnError)

	helpFlag        = flagset.Bool("help", false, "Print usage information and exit")
	versionFlag     = flagset.Bool("version", false, "Print version information and exit")
	versionJSONFlag = flagset.Bool("json", false, "Print version information in JSON format")
	configFlag      = flagset.String("config", "", "Path to a configuration file")
	printConfig     = flagset.Bool("print-config", false, "Print the configuration and exit")
	startTimeout    = flagset.Duration("start-timeout", 0, "Timeout for starting the node (default: no timeout)")
	shutdownTimeout = flagset.Duration("shutdown-timeout", 0, "Timeout for shutting down the node (default: no timeout)")

	conf       = config.NewDefaultConfig("").BindFlags("", flagset)
	daemonconf = daemoncmd.NewDefaultConfig().BindFlags("daemon.", flagset)
)

func Execute() error {
	// Parse flags and read in configurations
	err := flagset.Parse(os.Args[1:])
	if err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			return nil
		}
		return err
	}
	if *helpFlag {
		Usage()
		return nil
	}
	version := version.GetBuildInfo()

	// Dump the version and exit
	if *versionFlag || len(os.Args) > 1 && os.Args[1] == "version" {
		if *versionJSONFlag {
			fmt.Println(version.PrettyJSON("webmesh-node"))
			return nil
		}
		fmt.Println("Webmesh Node")
		fmt.Println("    Version:    ", version.Version)
		fmt.Println("    Git Commit: ", version.GitCommit)
		fmt.Println("    Build Date: ", version.BuildDate)
		return nil
	}
	// Load the configuration
	var configs []string
	if *configFlag != "" {
		configs = append(configs, *configFlag)
	}
	err = conf.LoadFrom(flagset, configs)
	if err != nil {
		return err
	}
	// Dump the config and exit
	if *printConfig {
		out, err := json.MarshalIndent(conf, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(out))
		return nil
	}
	// Setup logging and a base context
	log := logging.SetupLogging(conf.Global.LogLevel, conf.Global.LogFormat)
	ctx := context.WithLogger(context.Background(), log)
	if daemonconf.Enabled {
		// Start the node as an application daemon
		if err := daemonconf.Validate(); err != nil {
			return err
		}
		return daemoncmd.Run(context.Background(), *daemonconf)
	}
	// Apply globals
	conf, err = conf.Global.ApplyGlobals(ctx, conf)
	if err != nil {
		return err
	}
	// Validate the configuration if we are not running in daemon mode.
	err = conf.Validate()
	if err != nil {
		if errors.Is(err, config.ErrNoMesh) {
			// Display usage if no mesh is configured
			Usage()
			fmt.Fprintln(os.Stderr, "No mesh configured")
			os.Exit(1)
		}
		return err
	}

	// Time to get going
	log.Info("Starting webmesh node",
		slog.String("version", version.Version),
		slog.String("commit", version.GitCommit),
		slog.String("buildDate", version.BuildDate),
	)
	// Log all options at debug level
	log.Debug("Current configuration", slog.Any("options", conf.ToMapStructure()))
	if *startTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *startTimeout)
		defer cancel()
	}
	if len(conf.Bridge.Meshes) > 0 {
		// Start a bridged connection
		return bridgecmd.RunBridgeConnection(ctx, conf.Bridge)
	}
	// We run in "embedded mode"
	node, err := embed.NewNode(ctx, embed.Options{
		Config: conf,
	})
	if err != nil {
		return err
	}
	err = node.Start(ctx)
	if err != nil {
		return err
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case err = <-node.Errors():
		return err
	case <-sig:
	}
	if *shutdownTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.WithLogger(context.Background(), log), *shutdownTimeout)
		defer cancel()
	}
	return node.Stop(ctx)
}
