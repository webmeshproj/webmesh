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
	"encoding/base64"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/exp/slog"

	"github.com/webmeshproj/webmesh/pkg/ctlcmd/connect"
	"github.com/webmeshproj/webmesh/pkg/net/wireguard"
)

var connectOpts connect.Options
var connectLogLevel string

func init() {
	flags := connectCmd.Flags()
	flags.StringVar(&connectOpts.InterfaceName, "interface-name", wireguard.DefaultInterfaceName, "name of the wireguard interface to use")
	flags.Uint16Var(&connectOpts.ListenPort, "listen-port", 51820, "port for wireguard to listen on")
	flags.BoolVar(&connectOpts.ForceTUN, "force-tun", false, "force the use of a TUN interface")
	flags.BoolVar(&connectOpts.Modprobe, "modprobe", false, "attempt to load the wireguard kernel module")
	flags.StringVar(&connectOpts.JoinServer, "join-server", "", "address of the join server to use")
	flags.Uint16Var(&connectOpts.RaftPort, "raft-port", 9443, "port to use for the Raft transport")
	flags.StringVar(&connectOpts.TLSCertFile, "tls-cert-file", "", "path to a TLS certificate file to use for mTLS")
	flags.StringVar(&connectOpts.TLSKeyFile, "tls-key-file", "", "path to a TLS key file to use for mTLS")
	flags.StringVar(&connectOpts.TLSCAFile, "tls-ca-file", "", "path to a CA file for verifying the join server's certificate")
	flags.BoolVar(&connectOpts.VerifyChainOnly, "verify-chain-only", false, "only verify the join server's certificate chain")
	flags.BoolVar(&connectOpts.Insecure, "insecure", false, "do not use TLS when joining the cluster")
	flags.BoolVar(&connectOpts.NoIPv4, "no-ipv4", false, "do not use IPv4 when joining the cluster")
	flags.BoolVar(&connectOpts.NoIPv6, "no-ipv6", false, "do not use IPv6 when joining the cluster")
	flags.BoolVar(&connectOpts.LocalDNS, "local-dns", false, "start a local MeshDNS server")
	flags.Uint16Var(&connectOpts.LocalDNSPort, "local-dns-port", 5353, "port to use for the local MeshDNS server")

	flags.StringVar(&connectLogLevel, "log-level", "info", "log level to use")
	rootCmd.AddCommand(connectCmd)
}

var connectCmd = &cobra.Command{
	Use:          "connect",
	Short:        "Connect as an ephemeral node in the cluster",
	Aliases:      []string{"c", "conn"},
	SilenceUsage: true,
	RunE:         doConnect,
}

func doConnect(cmd *cobra.Command, args []string) error {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: func() slog.Level {
			switch strings.ToLower(connectLogLevel) {
			case "debug":
				return slog.LevelDebug
			case "info":
				return slog.LevelInfo
			case "warn":
				return slog.LevelWarn
			case "error":
				return slog.LevelError
			default:
				return slog.LevelInfo
			}
		}(),
	})))
	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()
	if connectOpts.JoinServer == "" {
		connectOpts.JoinServer = cliConfig.GetCurrentCluster().Server
		connectOpts.VerifyChainOnly = cliConfig.GetCurrentCluster().TLSVerifyChainOnly
		connectOpts.Insecure = cliConfig.GetCurrentCluster().Insecure
		if connectOpts.JoinServer == "" {
			return fmt.Errorf("no join server specified")
		}
	}
	// Take our TLS configurations from the CLI config
	// if not specified on the command line.
	if !connectOpts.Insecure {
		if connectOpts.TLSCertFile == "" {
			certData := cliConfig.GetCurrentUser().ClientCertificateData
			if certData == "" {
				return fmt.Errorf("no TLS certificate data found")
			}
			decoded, err := base64.StdEncoding.DecodeString(certData)
			if err != nil {
				return err
			}
			tmpCert, err := os.CreateTemp("", "webmesh-tls-cert-*.pem")
			if err != nil {
				return err
			}
			defer os.Remove(tmpCert.Name())
			_, err = tmpCert.Write(decoded)
			if err != nil {
				return err
			}
			connectOpts.TLSCertFile = tmpCert.Name()
		}
		if connectOpts.TLSKeyFile == "" {
			keyData := cliConfig.GetCurrentUser().ClientKeyData
			if keyData == "" {
				return fmt.Errorf("no TLS key data found")
			}
			decoded, err := base64.StdEncoding.DecodeString(keyData)
			if err != nil {
				return err
			}
			tmpKey, err := os.CreateTemp("", "webmesh-tls-key-*.pem")
			if err != nil {
				return err
			}
			defer os.Remove(tmpKey.Name())
			_, err = tmpKey.Write(decoded)
			if err != nil {
				return err
			}
			connectOpts.TLSKeyFile = tmpKey.Name()
		}
		if connectOpts.TLSCAFile == "" {
			caData := cliConfig.GetCurrentCluster().CertificateAuthorityData
			if caData != "" {
				decoded, err := base64.StdEncoding.DecodeString(caData)
				if err != nil {
					return err
				}
				tmpCA, err := os.CreateTemp("", "webmesh-tls-ca-*.pem")
				if err != nil {
					return err
				}
				defer os.Remove(tmpCA.Name())
				_, err = tmpCA.Write(decoded)
				if err != nil {
					return err
				}
				connectOpts.TLSCAFile = tmpCA.Name()
			}
		}
	}
	// Connect to the cluster.
	stop := make(chan struct{})
	errs := make(chan error, 1)
	go func() {
		defer close(errs)
		errs <- connect.Connect(ctx, connectOpts, stop)
	}()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errs:
		return err
	case <-sig:
	}
	cancel()
	close(stop)
	fmt.Println("shutting down, press Ctrl+C again to force")
	select {
	case err := <-errs:
		return err
	case <-sig:
		return fmt.Errorf("forced shutdown")
	}
}
