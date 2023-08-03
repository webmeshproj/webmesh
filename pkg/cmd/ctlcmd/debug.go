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
	"context"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
)

var (
	debugServer string
)

func init() {
	debugCmd.AddCommand(debugGetKeyCmd)
	debugCmd.AddCommand(debugListKeysCmd)
	debugCmd.AddCommand(debugPprofCmd)
	debugCmd.PersistentFlags().StringVar(&debugServer, "debug-server", "http://localhost:6060/debug", "Address of the debug server")
	rootCmd.AddCommand(debugCmd)
}

var debugCmd = &cobra.Command{
	Use:   "debug",
	Short: "Interact with a node's debug server",
}

var debugGetKeyCmd = &cobra.Command{
	Use:               "get-key [KEY]",
	Short:             "Get the value of a key from the node's data store",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeKeys,
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SetOutput(cmd.OutOrStdout())
		resp, err := doDebugGetKey(cmd.Context(), args[0])
		if err != nil {
			return err
		}
		cmd.Println(resp)
		return nil
	},
}

var debugListKeysCmd = &cobra.Command{
	Use:               "list-keys [PREFIX]",
	Short:             "List the keys in the node's data store",
	Args:              cobra.MaximumNArgs(1),
	ValidArgsFunction: completeKeys,
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SetOutput(cmd.OutOrStdout())
		var prefix string
		if len(args) > 0 {
			prefix = args[0]
		}
		resp, err := doDebugListKeys(cmd.Context(), prefix)
		if err != nil {
			return err
		}
		cmd.Println(strings.Join(resp, "\n"))
		return nil
	},
}

var debugPprofCmd = &cobra.Command{
	Use:   "pprof [PROFILE]",
	Short: "Convenience method for go tool pprof",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		debugServer = strings.TrimSuffix(debugServer, "/")
		debugPath := strings.TrimPrefix(args[0], "/")
		path := fmt.Sprintf("%s/pprof/%s", debugServer, debugPath)
		cmd.Printf("Running: go tool pprof %s\n", path)
		c := exec.CommandContext(cmd.Context(), "go", "tool", "pprof", path)
		c.Stdin = cmd.InOrStdin()
		c.Stdout = cmd.OutOrStdout()
		c.Stderr = cmd.ErrOrStderr()
		return c.Run()
	},
}

func completeKeys(cmd *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	resp, err := doDebugListKeys(cmd.Context(), toComplete)
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}
	return resp, cobra.ShellCompDirectiveNoFileComp
}

func doDebugGetKey(ctx context.Context, key string) (string, error) {
	req, err := newDebugDBRequest(ctx, "db/get", key)
	if err != nil {
		return "", fmt.Errorf("new request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("bad status: %s: %s", resp.Status, string(body))
	}
	return string(body), nil
}

func doDebugListKeys(ctx context.Context, prefix string) ([]string, error) {
	req, err := newDebugDBRequest(ctx, "db/list", prefix)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status: %s: %s", resp.Status, string(body))
	}
	bodyStr := strings.TrimSpace(string(body))
	return strings.Split(bodyStr, "\n"), nil
}

func newDebugDBRequest(ctx context.Context, path string, query string) (*http.Request, error) {
	debugServer = strings.TrimSuffix(debugServer, "/")
	path = strings.TrimPrefix(path, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/%s", debugServer, path), nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	q := req.URL.Query()
	q.Set("q", query)
	req.URL.RawQuery = q.Encode()
	return req, nil
}
