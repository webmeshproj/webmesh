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
	"bytes"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/webmeshproj/webmesh/pkg/crypto"
)

func init() {
	rootCmd.AddCommand(genKeyCmd)
	rootCmd.AddCommand(pubKeyCmd)
	rootCmd.AddCommand(keyIDCmd)
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
	Short: "Extract the public key from a private key or ID on stdin",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		data, err := io.ReadAll(cmd.InOrStdin())
		if err != nil {
			return err
		}
		data = bytes.TrimSpace(data)
		switch len(data) {
		case 92:
			// This is a private key.
			key, err := crypto.DecodePrivateKey(string(data))
			if err != nil {
				return err
			}
			encodedPub, err := key.PublicKey().Encode()
			if err != nil {
				return err
			}
			fmt.Println(encodedPub)
		case 52:
			// This is an ID with an embedded public key
			key, err := crypto.PubKeyFromID(string(data))
			if err != nil {
				return err
			}
			encodedPub, err := key.Encode()
			if err != nil {
				return err
			}
			fmt.Println(encodedPub)
		default:
			return fmt.Errorf("invalid key data")
		}
		return nil
	},
}

var keyIDCmd = &cobra.Command{
	Use:   "keyid",
	Short: "Extract the key ID from a private or public key on stdin",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		data, err := io.ReadAll(cmd.InOrStdin())
		if err != nil {
			return err
		}
		data = bytes.TrimSpace(data)
		switch len(data) {
		case 0:
			return fmt.Errorf("no data on stdin")
		case 92:
			// Private key
			key, err := crypto.DecodePrivateKey(string(data))
			if err != nil {
				return err
			}
			fmt.Println(key.ID())
		case 48:
			// Public key
			key, err := crypto.DecodePublicKey(string(data))
			if err != nil {
				return err
			}
			fmt.Println(key.ID())
		default:
			return fmt.Errorf("invalid key data")
		}
		return nil
	},
}
