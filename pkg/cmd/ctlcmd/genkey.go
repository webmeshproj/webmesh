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
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/webmeshproj/webmesh/pkg/crypto"
)

func init() {
	rootCmd.AddCommand(genKeyCmd)
	rootCmd.AddCommand(pubKeyCmd)
}

var genKeyCmd = &cobra.Command{
	Use:   "genkey",
	Short: "Generate a private key for use with webmesh",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		key, err := crypto.GenerateKey()
		if err != nil {
			return err
		}
		encoded, err := key.Encode()
		if err != nil {
			return err
		}
		fmt.Println(encoded)
		return nil
	},
}

var pubKeyCmd = &cobra.Command{
	Use:   "pubkey",
	Short: "Extract the public key from a private key on stdin",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		data, err := io.ReadAll(cmd.InOrStdin())
		if err != nil {
			return err
		}
		key, err := crypto.DecodePrivateKey(strings.TrimSpace(string(data)))
		if err != nil {
			return err
		}
		encodedPub, err := key.PublicKey().Encode()
		if err != nil {
			return err
		}
		fmt.Println(encodedPub)
		return nil
	},
}
