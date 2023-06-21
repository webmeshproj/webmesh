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
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/pion/webrtc/v3"
	"github.com/spf13/cobra"

	"github.com/webmeshproj/node/pkg/ctlcmd/portforward"
	"github.com/webmeshproj/node/pkg/net/datachannels"
)

func init() {
	s := webrtc.SettingEngine{}
	s.DetachDataChannels()
	WebRTC = webrtc.NewAPI(webrtc.WithSettingEngine(s))
}

var (
	portForwardProtocol string
	portForwardAddress  string

	// WebRTC is the WebRTC API.
	WebRTC *webrtc.API
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
	client, closer, err := cliConfig.NewWebRTCClient()
	if err != nil {
		return err
	}
	defer closer.Close()
	pc, err := datachannels.NewClientPeerConnection(cmd.Context(), &datachannels.ClientOptions{
		Client:      client,
		NodeID:      nodeID,
		Protocol:    portForwardProtocol,
		Destination: spec.RemoteAddress,
		Port:        spec.RemotePort,
	})
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
