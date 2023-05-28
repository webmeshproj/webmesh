/*
Copyright 2023.

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
	"strings"
	"syscall"

	"github.com/pion/webrtc/v3"
	"github.com/spf13/cobra"

	"github.com/webmeshproj/node/pkg/ctlcmd/portforward"
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
	l, err := net.Listen(portForwardProtocol, net.JoinHostPort(portForwardAddress, strconv.Itoa(int(spec.LocalPort))))
	if err != nil {
		return fmt.Errorf("failed to listen on %s:%d: %w", portForwardAddress, spec.LocalPort, err)
	}
	defer l.Close()
	client, closer, err := cliConfig.NewWebRTCClient()
	if err != nil {
		return err
	}
	defer closer.Close()
	pc, err := portforward.NewPeerConnection(cmd.Context(), &portforward.Options{
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

	// Handle incoming connections
	go func() {
		cmd.Println("Forwarding connections",
			"from", l.Addr(),
			"via", nodeID,
			"to", spec.RemoteString(),
		)
		for {
			conn, err := l.Accept()
			if err != nil && err != net.ErrClosed && !strings.Contains(err.Error(), "use of closed network connection") {
				cmd.Printf("Failed to accept connection: %v\n", err)
				return
			}
			go pc.Handle(conn)
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
