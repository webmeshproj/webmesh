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
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	cmdconfig "github.com/webmeshproj/webmesh/pkg/cmd/ctlcmd/config"
	"github.com/webmeshproj/webmesh/pkg/config"
	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/embed"
	"github.com/webmeshproj/webmesh/pkg/logging"
)

var (
	connectWireGuardOpts = config.NewWireGuardOptions()
	connectDiscoveryOpts = config.NewDiscoveryOptions("", false)
	connectUseDNS        bool
	connectDisableIPv4   bool
	connectDisableIPv6   bool
	connectLogLevel      string
	connectLogFormat     string
	connectTimeout       time.Duration
)

func init() {
	connectFlags := connectCmd.Flags()
	// Make full-tunnel opt-in for the connect command.
	connectWireGuardOpts.DisableFullTunnel = true
	connectWireGuardOpts.BindFlags("wireguard.", connectFlags)
	connectDiscoveryOpts.BindFlags("discovery.", connectFlags)
	connectFlags.BoolVar(&connectUseDNS, "use-mesh-dns", false, "Configure the system to use MeshDNS")
	connectFlags.BoolVar(&connectDisableIPv4, "disable-ipv4", false, "Disable IPv4")
	connectFlags.BoolVar(&connectDisableIPv6, "disable-ipv6", false, "Disable IPv6")
	connectFlags.StringVar(&connectLogLevel, "log-level", "info", "Log level for the connection")
	connectFlags.StringVar(&connectLogFormat, "log-format", "text", "Log format for the connection, text or json")
	connectFlags.DurationVar(&connectTimeout, "timeout", 30*time.Second, "Timeout for connecting to the mesh")
	rootCmd.AddCommand(connectCmd)
}

var connectCmd = &cobra.Command{
	Use:   "connect",
	Short: "Connect to a webmesh network as an ephemeral node",
	RunE: func(cmd *cobra.Command, args []string) error {
		var key crypto.PrivateKey
		var err error
		user := cliConfig.GetCurrentUser()
		cluster := cliConfig.GetCurrentCluster()
		if user == nil {
			user = &cmdconfig.UserConfig{}
		}
		if cluster == nil {
			cluster = &cmdconfig.ClusterConfig{}
		}
		if user.IDAuthPrivateKey != "" {
			key, err = crypto.DecodePrivateKey(user.IDAuthPrivateKey)
		} else {
			key, err = connectWireGuardOpts.LoadKey(cmd.Context())
		}
		if err != nil {
			return err
		}
		log := logging.NewLogger(connectLogLevel, connectLogFormat)
		ctx := context.WithLogger(cmd.Context(), log)
		cancel := func() {}
		if connectTimeout > 0 {
			ctx, cancel = context.WithTimeout(ctx, connectTimeout)
		} else {
			ctx, cancel = context.WithCancel(ctx)
		}
		node, err := embed.NewNode(ctx, newEmbedOptions(user, cluster, key))
		if err != nil {
			return err
		}
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		go func() {
			defer cancel()
			select {
			case <-sig:
				cmd.Println("Received interrupt, cancelling connection...")
			case <-ctx.Done():
			}
		}()
		err = node.Start(ctx)
		if err != nil {
			return err
		}
		cancel()
		defer func() {
			err = node.Stop(context.Background())
			if err != nil {
				cmd.PrintErr(err)
			}
		}()
		select {
		case <-sig:
		case <-cmd.Context().Done():
		}
		cmd.Println("Terminating connection...")
		return nil
	},
}

func newEmbedOptions(user *cmdconfig.UserConfig, cluster *cmdconfig.ClusterConfig, key crypto.PrivateKey) embed.Options {
	return embed.Options{
		Config: &config.Config{
			Global: config.GlobalOptions{
				LogLevel:  connectLogLevel,
				LogFormat: connectLogFormat,
			},
			WireGuard: connectWireGuardOpts,
			Discovery: connectDiscoveryOpts,
			Auth: config.AuthOptions{
				IDAuth: config.IDAuthOptions{
					Enabled: user.IDAuthPrivateKey != "",
				},
				MTLS: config.MTLSOptions{
					CertData: user.ClientCertificateData,
					KeyData:  user.ClientKeyData,
				},
				Basic: config.BasicAuthOptions{
					Username: user.BasicAuthUsername,
					Password: user.BasicAuthPassword,
				},
				LDAP: config.LDAPAuthOptions{
					Username: user.LDAPUsername,
					Password: user.LDAPPassword,
				},
			},
			Mesh: config.MeshOptions{
				JoinAddress:                 cluster.Server,
				MaxJoinRetries:              5,
				UseMeshDNS:                  connectUseDNS,
				DisableIPv4:                 connectDisableIPv4,
				DisableIPv6:                 connectDisableIPv6,
				DisableFeatureAdvertisement: true,
				DisableDefaultIPAM:          true,
			},
			TLS: config.TLSOptions{
				CAData:             cluster.CertificateAuthorityData,
				VerifyChainOnly:    cluster.TLSVerifyChainOnly,
				InsecureSkipVerify: cluster.TLSSkipVerify,
				Insecure:           cluster.Insecure,
			},
			Storage: config.StorageOptions{
				InMemory:  true,
				Provider:  string(config.StorageProviderPassThrough),
				LogLevel:  connectLogLevel,
				LogFormat: connectLogFormat,
			},
			Services: config.ServiceOptions{
				API: config.APIOptions{Disabled: true},
			},
		},
		Key: key,
	}
}
