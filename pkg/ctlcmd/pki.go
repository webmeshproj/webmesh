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
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/webmeshproj/node/pkg/ctlcmd/pki"
)

var (
	pkiDirectory string
	genOpts      = &pki.GenerateOptions{}
	issueOpts    = &pki.IssueOptions{}
)

func init() {
	pkiCmd.PersistentFlags().StringVarP(&pkiDirectory, "pki-directory", "d", "", "Path to the PKI directory")
	cobra.CheckErr(pkiCmd.MarkPersistentFlagRequired("pki-directory"))

	initPkiCmd.Flags().StringVar(&genOpts.CAName, "ca-name", pki.DefaultCAName, "The subject name to assign the CA certificate")
	initPkiCmd.Flags().StringVar(&genOpts.KeyType, "key-type", pki.DefaultKeyType, "The key type to use for the CA and Admin certificates")
	initPkiCmd.Flags().IntVar(&genOpts.KeySize, "key-size", pki.DefaultKeySize, "The key size to use for the CA and Admin certificates")
	initPkiCmd.Flags().StringVar(&genOpts.AdminName, "admin-name", pki.DefaultAdminName, "The subject name to assign the Admin certificate")
	initPkiCmd.Flags().DurationVar(&genOpts.CAExpiry, "ca-expiry", pki.DefaultCAExpiry, "The expiry to assign the CA certificate")
	initPkiCmd.Flags().DurationVar(&genOpts.AdminExpiry, "admin-expiry", pki.DefaultNodeExpiry, "The expiry to assign the Admin certificate")
	cobra.CheckErr(initPkiCmd.RegisterFlagCompletionFunc("key-type", completeKeyTypes))
	cobra.CheckErr(initPkiCmd.RegisterFlagCompletionFunc("key-size", completeKeySizes))

	issueCmd.Flags().StringVar(&issueOpts.Name, "name", "", "The subject name to assign the certificate")
	issueCmd.Flags().StringVar(&issueOpts.KeyType, "key-type", pki.DefaultKeyType, "The key type to use for the certificate")
	issueCmd.Flags().IntVar(&issueOpts.KeySize, "key-size", pki.DefaultKeySize, "The key size to use for the certificate")
	issueCmd.Flags().DurationVar(&issueOpts.Expiry, "expiry", pki.DefaultNodeExpiry, "The expiry to assign the certificate")
	cobra.CheckErr(issueCmd.MarkFlagRequired("name"))
	cobra.CheckErr(issueCmd.RegisterFlagCompletionFunc("key-type", completeKeyTypes))
	cobra.CheckErr(issueCmd.RegisterFlagCompletionFunc("key-size", completeKeySizes))

	pkiCmd.AddCommand(initPkiCmd)
	pkiCmd.AddCommand(issueCmd)
	rootCmd.AddCommand(pkiCmd)
}

var pkiCmd = &cobra.Command{
	Use:   "pki",
	Short: "Manage the PKI for a cluster using mTLS",
}

var initPkiCmd = &cobra.Command{
	Use:   "init",
	Short: "Initializes the PKI for a cluster using mTLS",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		err := pki.New(pkiDirectory).Generate(genOpts)
		if err != nil {
			return err
		}
		cmd.Println("PKI initialized at", pkiDirectory)
		return nil
	},
}

var issueCmd = &cobra.Command{
	Use:   "issue",
	Short: "Issues a certificate for a node",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		err := pki.New(pkiDirectory).Issue(issueOpts)
		if err != nil {
			return err
		}
		cmd.Println("Certificate issued at", filepath.Join(pkiDirectory, pki.NodesDirectory, issueOpts.Name))
		return nil
	},
}

func completeKeyTypes(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	return []string{"ecdsa", "rsa"}, cobra.ShellCompDirectiveNoFileComp
}

func completeKeySizes(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	return []string{"256", "384", "521", "2048", "4096"}, cobra.ShellCompDirectiveNoFileComp
}
