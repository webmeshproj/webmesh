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

// Package connect contains an implementation of the connect subcommand.
// It is used to connect to the mesh as an ephemeral node. It makes certain
// assumptions about the local environment. For example, it assumes the
// local hostname or a random UUID for the local node ID, an in-memory
// raft store, and to join the cluster as an observer.
package connect

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/webmeshproj/webmesh/pkg/services/meshdns"
	"github.com/webmeshproj/webmesh/pkg/store"
)

// Options are options for configuring the connect command.
type Options struct {
	// InterfaceName is the name of the wireguard interface to use.
	InterfaceName string
	// ListenPort is the port for wireguard to listen on.
	ListenPort uint16
	// ForceTUN is whether to force the use of a TUN interface.
	ForceTUN bool
	// Modprobe is whether to attempt to load the wireguard kernel module.
	Modprobe bool
	// JoinServer is the address of the join server to use.
	JoinServer string
	// RaftPort is the port to use for the Raft transport.
	RaftPort uint16
	// TLSCertFile is the path to a TLS certificate file to use
	// for mTLS.
	TLSCertFile string
	// TLSKeyFile is the path to a TLS key file to use for mTLS.
	TLSKeyFile string
	// TLSCAFile is the path to a CA file for verifying the join
	// server's certificate
	TLSCAFile string
	// VerifyChainOnly is whether to only verify the join server's
	// certificate chain.
	VerifyChainOnly bool
	// Insecure is whether to not use TLS when joining the cluster.
	// This assumes an insecure raft transport as well.
	Insecure bool
	// NoIPv4 is whether to not use IPv4 when joining the cluster.
	NoIPv4 bool
	// NoIPv6 is whether to not use IPv6 when joining the cluster.
	NoIPv6 bool
	// LocalDNS is whether to start a local MeshDNS server.
	LocalDNS bool
	// LocalDNSPort is the port to use for the local MeshDNS server.
	LocalDNSPort uint16
}

// Connect connects to the mesh as an ephemeral node. The context
// is used to cancel the initial join to the cluster. The stopChan
// is used to stop the node.
func Connect(ctx context.Context, opts Options, stopChan chan struct{}) error {
	// Configure the raft store
	storeOpts := store.NewOptions()
	storeOpts.Raft.InMemory = true
	storeOpts.Raft.ListenAddress = fmt.Sprintf(":%d", opts.RaftPort)
	storeOpts.Raft.LeaveOnShutdown = true
	storeOpts.Raft.ShutdownTimeout = time.Second * 10
	if opts.TLSCertFile != "" && opts.TLSKeyFile != "" {
		storeOpts.Auth.MTLS = &store.MTLSOptions{
			CertFile: opts.TLSCertFile,
			KeyFile:  opts.TLSKeyFile,
		}
	}
	storeOpts.TLS.CAFile = opts.TLSCAFile
	storeOpts.TLS.Insecure = opts.Insecure
	storeOpts.TLS.VerifyChainOnly = opts.VerifyChainOnly
	storeOpts.Mesh.JoinAddress = opts.JoinServer
	storeOpts.Mesh.NoIPv4 = opts.NoIPv4
	storeOpts.Mesh.NoIPv6 = opts.NoIPv6
	storeOpts.WireGuard.InterfaceName = opts.InterfaceName
	storeOpts.WireGuard.ListenPort = int(opts.ListenPort)
	storeOpts.WireGuard.ForceTUN = opts.ForceTUN
	storeOpts.WireGuard.Modprobe = opts.Modprobe
	storeOpts.WireGuard.PersistentKeepAlive = time.Second * 10

	// Create the store
	st, err := store.New(storeOpts)
	if err != nil {
		return fmt.Errorf("create store: %w", err)
	}
	if err := st.Open(ctx); err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	select {
	case <-stopChan:
		return st.Close()
	case <-ctx.Done():
		err = ctx.Err()
		closeErr := st.Close()
		if closeErr != nil {
			err = fmt.Errorf("%w: %w", ctx.Err(), closeErr)
		}
		return err
	case <-st.ReadyNotify(ctx):
		if ctx.Err() != nil {
			err = fmt.Errorf("wait for store ready: %w", ctx.Err())
			closeErr := st.Close()
			if closeErr != nil {
				err = fmt.Errorf("%w: %w", err, closeErr)
			}
			return err
		}
	}

	if opts.LocalDNS {
		// Start a local MeshDNS server
		server := meshdns.NewServer(st, &meshdns.Options{
			UDPListenAddr: fmt.Sprintf(":%d", opts.LocalDNSPort),
			Domain:        "webmesh.internal.",
		})
		go func() {
			go func() {
				if err := server.ListenAndServe(); err != nil {
					fmt.Fprintf(os.Stderr, "dns serve: %v\n", err)
				}
			}()
			<-stopChan
			if err := server.Shutdown(); err != nil {
				fmt.Fprintf(os.Stderr, "dns shutdown: %v\n", err)
			}
		}()
	}

	<-stopChan
	return st.Close()
}
