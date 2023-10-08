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

package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/webmeshproj/webmesh/pkg/config"
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/embed"
	"github.com/webmeshproj/webmesh/pkg/meshnet/endpoints"
)

func main() {
	psk := flag.String("psk", "", "Pre-shared key")
	loglevel := flag.String("loglevel", "", "Log level (default: silent)")
	flag.Parse()

	mode := "server"
	if *psk != "" {
		mode = "client"
	}

	switch mode {
	case "server":
		if err := runServer(*loglevel); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "client":
		if err := runClient(*loglevel, *psk); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	default:
		flag.Usage()
		os.Exit(1)
	}
}

// We explicitly set unique ports in case we are being run on the
// same machine.

func runServer(loglevel string) error {
	ctx := context.Background()
	eps, err := endpoints.Detect(ctx, endpoints.DetectOpts{
		DetectIPv6:     true,
		DetectPrivate:  true,
		SkipInterfaces: []string{},
	})
	if err != nil {
		return err
	}
	if len(eps) == 0 {
		return errors.New("no endpoints detected")
	}

	psk, err := crypto.GeneratePSK()
	if err != nil {
		return err
	}

	fmt.Printf("Bootstrapping network with PSK: %s\n", string(psk))

	conf := config.NewDefaultConfig("server-node")
	conf.Global.LogLevel = loglevel
	conf.Services.API.ListenAddress = "[::]:8443"
	conf.Services.API.Insecure = true
	conf.Storage.Raft.ListenAddress = "[::]:9000"
	conf.Storage.InMemory = true
	conf.WireGuard.ListenPort = 61820
	conf.WireGuard.InterfaceName = "meshserver0"
	conf.Bootstrap.Enabled = true
	conf.TLS.Insecure = true
	conf.Mesh.PrimaryEndpoint = eps[0].Addr().String()
	conf.Discovery.Announce = true
	conf.Discovery.Rendezvous = string(psk)
	conf.Discovery.LocalAddrs = []string{"ip6/::1/tcp/61820"}

	conn, err := embed.NewNode(context.Background(), embed.Options{Config: conf})
	if err != nil {
		return err
	}

	err = conn.Start(ctx)
	if err != nil {
		return err
	}
	defer conn.Stop(ctx)

	// Start a chat server on the wireguard interface.
	addr := conn.AddressV6().Addr()
	fmt.Printf("Chat server listening on %s:8080\n", addr)
	l, err := net.Listen("tcp", net.JoinHostPort(addr.String(), "8080"))
	if err != nil {
		return err
	}
	defer l.Close()

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				fmt.Printf("Error accepting connection: %v\n", err)
				continue
			}
			fmt.Print("New connection from ", conn.RemoteAddr(), "\n")
			go handleChat(conn)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	return nil
}

func runClient(loglevel string, psk string) error {
	fmt.Println("Joining server at pre-shared key", psk)
	ctx := context.Background()

	conf := config.NewDefaultConfig("client-node")
	conf.Global.LogLevel = loglevel
	conf.Services.API.ListenAddress = "[::]:8444"
	conf.Services.API.Insecure = true
	conf.WireGuard.ListenPort = 61821
	conf.WireGuard.InterfaceName = "meshclient0"
	conf.Discovery.Rendezvous = psk
	conf.Discovery.Discover = true
	conf.Discovery.LocalAddrs = []string{"ip6/::1/tcp/61821"}
	conf.TLS.Insecure = true

	conn, err := embed.NewNode(context.Background(), embed.Options{Config: conf})
	if err != nil {
		return err
	}

	err = conn.Start(ctx)
	if err != nil {
		return err
	}
	defer conn.Stop(ctx)

	// Dial the chat server on the wireguard interface.
	c, err := conn.Dial(ctx, "tcp", "server-node:8080")
	if err != nil {
		return err
	}
	go handleChat(c)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	return nil
}

func handleChat(conn net.Conn) {
	defer conn.Close()
	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
	go writeData(rw)
	readData(rw)
}

func readData(rw *bufio.ReadWriter) {
	for {
		str, err := rw.ReadString('\n')
		if err != nil {
			fmt.Println("Error reading from buffer", "error", err.Error())
			return
		}
		if str == "" {
			return
		}
		if str != "\n" {
			fmt.Printf("\x1b[32m%s\x1b[0m> ", str)
		}
	}
}

func writeData(rw *bufio.ReadWriter) {
	stdReader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("> ")
		sendData, err := stdReader.ReadString('\n')
		if err != nil {
			fmt.Println("Error reading from stdin", "error", err.Error())
			return
		}
		_, err = rw.WriteString(fmt.Sprintf("%s\n", sendData))
		if err != nil {
			fmt.Println("Error writing to buffer", "error", err.Error())
			return
		}
		err = rw.Flush()
		if err != nil {
			fmt.Println("Error flushing buffer", "error", err.Error())
			return
		}
	}
}
