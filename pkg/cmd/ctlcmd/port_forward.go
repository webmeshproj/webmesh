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
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/spf13/cobra"
	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/cmd/ctlcmd/portforward"
	"github.com/webmeshproj/webmesh/pkg/net/datachannels"
	"github.com/webmeshproj/webmesh/pkg/net/transport"
	"github.com/webmeshproj/webmesh/pkg/net/transport/tcp"
)

var (
	portForwardProtocol string
	portForwardAddress  string
)

func init() {
	portForwardCmd.Flags().StringVar(&portForwardProtocol, "protocol", "tcp", "Protocol to forward")
	portForwardCmd.Flags().StringVar(&portForwardAddress, "address", "127.0.0.1", "Address to listen on")
	rootCmd.AddCommand(portForwardCmd)
}

var portForwardCmd = &cobra.Command{
	Use:               "port-forward NODE_ID [LOCAL_PORT:[REMOTE_ADDRESS]:]REMOTE_PORT",
	Short:             "Forward ports to services running in the mesh",
	Args:              cobra.ExactArgs(2),
	ValidArgsFunction: completeNodes(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		nodeID, portForwardSpec := args[0], args[1]
		return portForward(cmd, nodeID, portForwardSpec)
	},
}

func portForward(cmd *cobra.Command, nodeID string, portForwardSpec string) error {
	spec, err := portforward.ParsePortForwardSpec(portForwardSpec)
	if err != nil {
		return fmt.Errorf("failed to parse port forward spec: %w", err)
	}
	creds, err := cliConfig.GetDialOptions()
	if err != nil {
		return fmt.Errorf("failed to get dial options: %w", err)
	}
	pc, err := datachannels.NewPeerConnectionClient(cmd.Context(), portForwardProtocol, tcp.NewSignalTransport(tcp.WebRTCSignalOptions{
		Resolver: transport.FeatureResolverFunc(func(ctx context.Context, lookup v1.Feature) ([]netip.AddrPort, error) {
			// Return the server address from our config
			addrport, err := netip.ParseAddrPort(cliConfig.GetCurrentCluster().Server)
			if err != nil {
				return nil, err
			}
			return []netip.AddrPort{addrport}, nil
		}),
		Credentials: creds,
		NodeID:      nodeID,
		TargetProto: portForwardProtocol,
		TargetAddr:  netip.MustParseAddrPort(net.JoinHostPort(portForwardAddress, strconv.Itoa(int(spec.RemotePort)))),
	}))
	if err != nil {
		return fmt.Errorf("failed to create peer connection: %w", err)
	}
	defer pc.Close()

	// Handle errors from the peer connection
	go func() {
		for err := range pc.Errors() {
			cmd.Printf("Peer connection error: %v\n", err)
			select {
			case <-pc.Ready():
				continue
			default:
				os.Exit(1)
			}
		}
	}()

	// Block until the connection is ready or fails
	select {
	case <-pc.Ready():
	case <-pc.Closed():
		cmd.Println("Peer connection failed to become ready")
		os.Exit(1)
	}

	portForwardAddr := net.JoinHostPort(portForwardAddress, strconv.Itoa(int(spec.LocalPort)))

	// Start the listener
	go func() {
		cmd.Println("Forwarding connections",
			"from", portForwardAddr,
			"via", nodeID,
			"to", spec.RemoteString(),
		)
		if err := pc.ListenAndServe(cmd.Context(), portForwardProtocol, portForwardAddr); err != nil {
			cmd.Printf("Failed to serve: %v\n", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case <-pc.Closed():
		cmd.Println("Peer connection closed")
	case <-sig:
		cmd.Println("Received interrupt, shutting down")
	}
	return nil
}
