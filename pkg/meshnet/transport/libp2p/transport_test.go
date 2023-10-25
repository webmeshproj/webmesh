//go:build !wasm

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

package libp2p

import (
	"testing"

	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/crypto"
)

func TestRPCTransport(t *testing.T) {
	ctx := context.Background()

	t.Run("WithoutCredentials", func(t *testing.T) {
		// Setup the libp2p hosts
		serverKey := crypto.MustGenerateKey()
		clientKey := crypto.MustGenerateKey()
		server, err := NewHost(ctx, HostOptions{
			Key: serverKey,
		})
		if err != nil {
			t.Fatal(err)
		}
		client, err := NewHost(ctx, HostOptions{
			Key:                  clientKey,
			UncertifiedPeerstore: true,
		})
		if err != nil {
			defer server.Close(ctx)
			t.Fatal(err)
		}
		// Create a dummy gRPC server and register an unimplemented
		// service.
		srv := grpc.NewServer()
		t.Cleanup(srv.Stop)
		v1.RegisterMeshServer(srv, v1.UnimplementedMeshServer{})
		go func() {
			err := srv.Serve(server.RPCListener())
			if err != nil {
				t.Log("Server error:", err)
			}
		}()
		// Create a client transport.
		rt := NewTransport(client, grpc.WithTransportCredentials(insecure.NewCredentials()))
		// Test the transport for each of the host's addresses.
		defer client.Close(ctx)
		for _, addr := range server.Host().Addrs() {
			c, err := rt.Dial(ctx, server.ID(), addr.String())
			if err != nil {
				t.Fatal("Dial server address:", err)
			}
			defer c.Close()
			cli := v1.NewMeshClient(c)
			_, err = cli.GetNode(ctx, &v1.GetNodeRequest{})
			// We should actually get an unimplemented error here.
			if err == nil {
				t.Fatal("Expected error, got nil")
			}
			if status.Code(err) != codes.Unimplemented {
				t.Fatal("Expected unimplemented error, got", err)
			}
		}
	})

	t.Run("WithCredentials", func(t *testing.T) {
		// Setup the libp2p hosts
		serverKey := crypto.MustGenerateKey()
		clientKey := crypto.MustGenerateKey()
		server, err := NewHost(ctx, HostOptions{
			Key: serverKey,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer server.Close(ctx)
		client, err := NewHost(ctx, HostOptions{
			Key: clientKey,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close(ctx)
		// TODO:
	})

	t.Run("WithDiscovery", func(t *testing.T) {})
}
