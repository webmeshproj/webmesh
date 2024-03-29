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
	"crypto/tls"
	"crypto/x509"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/record"
	"github.com/multiformats/go-multiaddr"
	v1 "github.com/webmeshproj/api/go/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/meshnet/transport"
	"github.com/webmeshproj/webmesh/pkg/plugins"
	"github.com/webmeshproj/webmesh/pkg/plugins/builtins/idauth"
	"github.com/webmeshproj/webmesh/pkg/plugins/clients"
)

var testNode = &v1.MeshNode{
	Id:        "test-node",
	PublicKey: must(crypto.MustGenerateKey().PublicKey().Encode),
}

func must(fn func() (string, error)) string {
	s, err := fn()
	if err != nil {
		panic(err)
	}
	return s
}

type TestMeshAPI struct {
	v1.UnimplementedMeshServer
}

func (*TestMeshAPI) GetMeshGraph(context.Context, *emptypb.Empty) (*v1.MeshGraph, error) {
	// Leave unimplemented.
	return nil, status.Errorf(codes.Unimplemented, "unimplemented")
}

func (*TestMeshAPI) GetNode(context.Context, *v1.GetNodeRequest) (*v1.MeshNode, error) {
	// Return a dummy node
	return testNode, nil
}

func (*TestMeshAPI) ListNodes(context.Context, *emptypb.Empty) (*v1.NodeList, error) {
	// Use for a custom error message
	return nil, status.Errorf(codes.Internal, "something went wrong")
}

func RunClientConnTests(ctx context.Context, t *testing.T, c transport.RPCClientConn) {
	t.Helper()
	cli := v1.NewMeshClient(c)
	_, err := cli.GetMeshGraph(ctx, &emptypb.Empty{})
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	if status.Code(err) != codes.Unimplemented {
		t.Fatal("Expected unimplemented error, got", err)
	}
	_, err = cli.ListNodes(ctx, &emptypb.Empty{})
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	if status.Code(err) != codes.Internal {
		t.Fatal("Expected internal error, got", err)
	}
	node, err := cli.GetNode(ctx, &v1.GetNodeRequest{})
	if err != nil {
		t.Fatal("GetNode:", err)
	}
	if node.Id != testNode.Id {
		t.Fatal("Expected node ID", testNode.Id, "got", node.Id)
	}
	if node.PublicKey != testNode.PublicKey {
		t.Fatal("Expected node public key", testNode.PublicKey, "got", node.PublicKey)
	}
}

func TestRPCTransport(t *testing.T) {
	ctx := context.Background()

	t.Run("WithCertifiedPeerstore", func(t *testing.T) {
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
			Key: clientKey,
		})
		if err != nil {
			defer server.Close()
			t.Fatal(err)
		}
		// Sign and consume a signed record of the host addresses.
		peerrec := peer.NewPeerRecord()
		peerrec.Addrs = server.Host().Addrs()
		peerrec.PeerID = peer.ID(server.ID())
		envelope, err := record.Seal(peerrec, serverKey.AsIdentity())
		if err != nil {
			defer server.Close()
			defer client.Close()
			t.Fatal(err)
		}
		err = client.AddAddrs(server.Host().Addrs(), peer.ID(server.ID()), peerstore.PermanentAddrTTL)
		if err != nil {
			defer server.Close()
			defer client.Close()
			t.Fatal(err)
		}
		err = client.ConsumePeerRecord(envelope, peerstore.PermanentAddrTTL)
		if err != nil {
			defer server.Close()
			defer client.Close()
			t.Fatal(err)
		}
		// Create a dummy gRPC server and register an unimplemented service.
		srv := grpc.NewServer()
		v1.RegisterMeshServer(srv, &TestMeshAPI{})
		go func() {
			err := srv.Serve(server.RPCListener())
			if err != nil {
				t.Log("Server error:", err)
			}
		}()
		t.Cleanup(srv.Stop)
		// Create a client transport.
		rt := NewTransport(client)
		t.Cleanup(func() { _ = client.Close() })

		t.Run("DialByID", func(t *testing.T) {
			c, err := rt.Dial(ctx, server.ID(), "")
			if err != nil {
				t.Fatal("Dial server address:", err)
			}
			defer c.Close()
			RunClientConnTests(ctx, t, c)
		})

		t.Run("DialByMultiaddr", func(t *testing.T) {
			for _, addr := range server.Host().Addrs() {
				c, err := rt.Dial(ctx, "", addr.String())
				if err != nil {
					t.Fatal("Dial server address:", err)
				}
				defer c.Close()
				RunClientConnTests(ctx, t, c)
			}
		})
	})

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
			defer server.Close()
			t.Fatal(err)
		}
		// Create a dummy gRPC server and register an unimplemented service.
		srv := grpc.NewServer()
		t.Cleanup(srv.Stop)
		v1.RegisterMeshServer(srv, &TestMeshAPI{})
		go func() {
			err := srv.Serve(server.RPCListener())
			if err != nil {
				t.Log("Server error:", err)
			}
		}()
		// Create a client transport.
		rt := NewTransport(client)
		// Test the transport for each of the host's addresses.
		defer client.Close()
		for _, addr := range server.Host().Addrs() {
			c, err := rt.Dial(ctx, server.ID(), addr.String())
			if err != nil {
				t.Fatal("Dial server address:", err)
			}
			defer c.Close()
			RunClientConnTests(ctx, t, c)
		}
	})

	t.Run("WithIDCredentials", func(t *testing.T) {
		// Setup the libp2p hosts
		serverKey := crypto.MustGenerateKey()
		clientKey := crypto.MustGenerateKey()
		unallowedKey := crypto.MustGenerateKey()
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
			defer server.Close()
			t.Fatal(err)
		}
		unallowedClient, err := NewHost(ctx, HostOptions{
			Key:                  unallowedKey,
			UncertifiedPeerstore: true,
		})
		if err != nil {
			defer server.Close()
			defer client.Close()
			t.Fatal(err)
		}
		// Create a dummy gRPC server that uses ID authentication
		// and register an unimplemented service.
		idauthsrv, err := idauth.NewWithConfig(ctx, idauth.Config{
			AllowedIDs: []string{clientKey.ID()},
		})
		if err != nil {
			t.Fatal(err)
		}
		idauthcli := clients.NewInProcessClient(idauthsrv)
		srv := grpc.NewServer(grpc.ChainUnaryInterceptor(plugins.NewAuthUnaryInterceptor(idauthcli.Auth())))
		t.Cleanup(srv.Stop)
		v1.RegisterMeshServer(srv, &TestMeshAPI{})
		go func() {
			err := srv.Serve(server.RPCListener())
			if err != nil {
				t.Log("Server error:", err)
			}
		}()
		// Test that an allowed ID can use the server.
		t.Run("AllowedID", func(t *testing.T) {
			defer client.Close()
			rt := NewTransport(client, idauth.NewCreds(clientKey), grpc.WithTransportCredentials(insecure.NewCredentials()))
			for _, addr := range server.Host().Addrs() {
				c, err := rt.Dial(ctx, server.ID(), addr.String())
				if err != nil {
					t.Fatal("Dial server address:", err)
				}
				defer c.Close()
				RunClientConnTests(ctx, t, c)
			}
		})
		// Test that an unallowed ID can use the server, but will be rejected.
		t.Run("UnallowedID", func(t *testing.T) {
			defer unallowedClient.Close()
			rt := NewTransport(unallowedClient, idauth.NewCreds(unallowedKey), grpc.WithTransportCredentials(insecure.NewCredentials()))
			for _, addr := range server.Host().Addrs() {
				c, err := rt.Dial(ctx, server.ID(), addr.String())
				if err != nil {
					t.Fatal("Dial server address:", err)
				}
				defer c.Close()
				cli := v1.NewMeshClient(c)
				_, err = cli.GetNode(ctx, &v1.GetNodeRequest{})
				// We should get an unauthenticated error here.
				if err == nil {
					t.Fatal("Expected error, got nil")
				}
				if status.Code(err) != codes.Unauthenticated {
					t.Fatal("Expected unauthenticated error, got", err)
				}
			}
		})
	})

	// The same tests as above but with doing an additional TLS upgrade.
	t.Run("WithTLSCredentials", func(t *testing.T) {
		t.Run("WithoutMTLS", func(t *testing.T) {
			server, err := NewHost(ctx, HostOptions{})
			if err != nil {
				t.Fatal(err)
			}
			client, err := NewHost(ctx, HostOptions{
				UncertifiedPeerstore: true,
			})
			if err != nil {
				defer server.Close()
				t.Fatal(err)
			}
			serverKey, serverCert, err := crypto.GenerateSelfSignedServerCert()
			if err != nil {
				defer server.Close()
				defer client.Close()
				t.Fatal(err)
			}
			tlsconf := &tls.Config{
				InsecureSkipVerify: true,
				Certificates: []tls.Certificate{{
					Certificate: [][]byte{serverCert.Raw},
					PrivateKey:  serverKey,
				}},
			}
			srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsconf)))
			t.Cleanup(srv.Stop)
			v1.RegisterMeshServer(srv, &TestMeshAPI{})
			go func() {
				err := srv.Serve(server.RPCListener())
				if err != nil {
					t.Log("Server error:", err)
				}
			}()
			// Create a client transport.
			rt := NewTransport(client, grpc.WithTransportCredentials(credentials.NewTLS(tlsconf)))
			// Test the transport for each of the host's addresses.
			defer client.Close()
			for _, addr := range server.Host().Addrs() {
				c, err := rt.Dial(ctx, server.ID(), addr.String())
				if err != nil {
					t.Fatal("Dial server address:", err)
				}
				defer c.Close()
				RunClientConnTests(ctx, t, c)
			}
		})

		t.Run("WithMTLS", func(t *testing.T) {
			// Generate a CA certificate and key.
			caPrivKey, caCert, err := crypto.GenerateCA(crypto.CACertConfig{})
			if err != nil {
				t.Fatal(err)
			}
			rootpool := x509.NewCertPool()
			rootpool.AddCert(caCert)
			// Generate a server certificate and key.
			serverKey, serverCert, err := crypto.IssueCertificate(crypto.IssueConfig{
				CommonName: "test-webmesh-server",
				KeyType:    crypto.TLSKeyWebmesh,
				CACert:     caCert,
				CAKey:      caPrivKey,
			})
			if err != nil {
				t.Fatal(err)
			}
			// Generate a client certificate and key.
			clientKey, clientCert, err := crypto.IssueCertificate(crypto.IssueConfig{
				CommonName: "test-webmesh-client",
				KeyType:    crypto.TLSKeyWebmesh,
				CACert:     caCert,
				CAKey:      caPrivKey,
			})
			if err != nil {
				t.Fatal(err)
			}
			servertlsconf := &tls.Config{
				InsecureSkipVerify:    true,
				VerifyPeerCertificate: crypto.VerifyCertificateChainOnly([]*x509.Certificate{caCert}),
				ClientAuth:            tls.RequireAndVerifyClientCert,
				ClientCAs:             rootpool,
				Certificates: []tls.Certificate{{
					Certificate: [][]byte{serverCert.Raw},
					PrivateKey:  serverKey,
				}}}
			clienttlsconf := &tls.Config{
				InsecureSkipVerify:    true,
				VerifyPeerCertificate: crypto.VerifyCertificateChainOnly([]*x509.Certificate{caCert}),
				RootCAs:               rootpool,
				Certificates: []tls.Certificate{{
					Certificate: [][]byte{clientCert.Raw},
					PrivateKey:  clientKey,
				}},
			}
			servercreds := grpc.Creds(credentials.NewTLS(servertlsconf))
			clientcreds := grpc.WithTransportCredentials(credentials.NewTLS(clienttlsconf))
			// Get started the same as the others above.
			server, err := NewHost(ctx, HostOptions{
				Key: crypto.MustPrivateKeyFromNative(serverKey),
			})
			if err != nil {
				t.Fatal(err)
			}
			srv := grpc.NewServer(servercreds)
			v1.RegisterMeshServer(srv, &TestMeshAPI{})
			go func() {
				err := srv.Serve(server.RPCListener())
				if err != nil {
					t.Log("Server error:", err)
				}
			}()
			t.Cleanup(srv.Stop)

			t.Run("ValidClientCertificate", func(t *testing.T) {
				client, err := NewHost(ctx, HostOptions{
					Key:                  crypto.MustPrivateKeyFromNative(clientKey),
					UncertifiedPeerstore: true,
				})
				if err != nil {
					t.Fatal(err)
				}
				// Create a client transport.
				rt := NewTransport(client, clientcreds)
				// Test the transport for each of the host's addresses.
				defer client.Close()
				for _, addr := range server.Host().Addrs() {
					c, err := rt.Dial(ctx, server.ID(), addr.String())
					if err != nil {
						t.Fatal("Dial server address:", err)
					}
					defer c.Close()
					RunClientConnTests(ctx, t, c)
				}
			})

			t.Run("InvalidClientCertificate", func(t *testing.T) {
				key, cert, err := crypto.GenerateSelfSignedServerCert()
				if err != nil {
					t.Fatal(err)
				}
				creds := grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
					InsecureSkipVerify:    true,
					VerifyPeerCertificate: crypto.VerifyCertificateChainOnly([]*x509.Certificate{caCert}),
					RootCAs:               rootpool,
					Certificates: []tls.Certificate{{
						Certificate: [][]byte{cert.Raw},
						PrivateKey:  key,
					}},
				}))
				client, err := NewHost(ctx, HostOptions{
					Key:                  crypto.MustGenerateKey(),
					UncertifiedPeerstore: true,
				})
				if err != nil {
					t.Fatal(err)
				}
				// Create a client transport.
				rt := NewTransport(client, creds)
				// Test the transport for each of the host's addresses.
				defer client.Close()
				for _, addr := range server.Host().Addrs() {
					c, err := rt.Dial(ctx, server.ID(), addr.String())
					if err != nil {
						t.Fatal("Dial server address:", err)
					}
					defer c.Close()
					cli := v1.NewMeshClient(c)
					_, err = cli.GetNode(ctx, &v1.GetNodeRequest{})
					if err == nil {
						t.Fatal("Expected error, got nil")
					}
					// We should get an unavailable here due to the TLS error
					if status.Code(err) != codes.Unavailable {
						t.Fatal("Expected unavailable error, got", err)
					}
					if !strings.Contains(err.Error(), "remote error: tls") {
						t.Fatal("Expected tls error, got", err)
					}
				}
			})
		})
	})
}

func TestDiscoveryRPCTransport(t *testing.T) {
	if os.Getenv("CI") == "true" {
		t.Skip("Skipping discovery transport test in CI")
	}
	ctx := context.Background()

	t.Run("Defaults", func(t *testing.T) {
		// Setup the server libp2p host.
		rendezvous := uuid.NewString()
		server, err := NewDiscoveryHost(ctx, HostOptions{
			ConnectTimeout: time.Second * 5,
			LocalAddrs: []multiaddr.Multiaddr{
				multiaddr.StringCast("/ip4/0.0.0.0/tcp/0"),
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		// Announce this host to the DHT and start a dummy server.
		server.Announce(ctx, rendezvous, time.Minute)
		t.Cleanup(func() { _ = server.Close() })
		srv := grpc.NewServer(grpc.Creds(insecure.NewCredentials()))
		v1.RegisterMeshServer(srv, &TestMeshAPI{})
		go func() {
			err := srv.Serve(server.RPCListener())
			if err != nil {
				t.Log("Server error:", err)
			}
		}()
		t.Cleanup(srv.Stop)
		// Create a client transport.
		rt, err := NewDiscoveryTransport(ctx, TransportOptions{
			Rendezvous: rendezvous,
			HostOptions: HostOptions{
				ConnectTimeout: time.Second * 5,
				LocalAddrs: []multiaddr.Multiaddr{
					multiaddr.StringCast("/ip4/0.0.0.0/tcp/0"),
				},
			},
			Credentials: []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())},
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = rt.(*rpcDiscoveryTransport).Close() })
		// Test the transport.
		dialctx, cancel := context.WithTimeout(ctx, time.Second*15)
		defer cancel()
		c, err := rt.Dial(dialctx, "", "")
		if err != nil {
			t.Fatal("Dial server address:", err)
		}
		defer c.Close()
		RunClientConnTests(ctx, t, c)
	})

	t.Run("PrestartedHosts", func(t *testing.T) {
		// Setup the libp2p hosts
		const connectTimeout = time.Second * 5
		const dialTimeout = time.Second * 15

		serverKey := crypto.MustGenerateKey()
		clientKey := crypto.MustGenerateKey()
		rendezvous := uuid.NewString()

		server, err := NewDiscoveryHost(ctx, HostOptions{
			Key:            serverKey,
			ConnectTimeout: connectTimeout,
			LocalAddrs: []multiaddr.Multiaddr{
				multiaddr.StringCast("/ip4/0.0.0.0/tcp/0"),
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		// Announce this host to the DHT and start a dummy server
		server.Announce(ctx, rendezvous, time.Minute)
		t.Cleanup(func() { _ = server.Close() })
		srv := grpc.NewServer(grpc.Creds(insecure.NewCredentials()))
		v1.RegisterMeshServer(srv, &TestMeshAPI{})
		go func() {
			err := srv.Serve(server.RPCListener())
			if err != nil {
				t.Log("Server error:", err)
			}
		}()
		t.Cleanup(srv.Stop)
		// Create a client transport.
		client, err := NewDiscoveryHost(ctx, HostOptions{
			Key:            clientKey,
			ConnectTimeout: connectTimeout,
			LocalAddrs: []multiaddr.Multiaddr{
				multiaddr.StringCast("/ip4/0.0.0.0/tcp/0"),
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })
		rt, err := NewDiscoveryTransport(ctx, TransportOptions{
			Host:        client,
			Rendezvous:  rendezvous,
			HostOptions: HostOptions{ConnectTimeout: connectTimeout},
			Credentials: []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())},
		})
		if err != nil {
			t.Fatal(err)
		}
		// Test the transport.
		dialctx, cancel := context.WithTimeout(ctx, dialTimeout)
		defer cancel()
		c, err := rt.Dial(dialctx, "", "")
		if err != nil {
			t.Fatal("Dial server address:", err)
		}
		defer c.Close()
		RunClientConnTests(ctx, t, c)
	})
}
