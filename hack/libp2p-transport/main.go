package main

import (
	"context"
	"fmt"
	"log"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/multiformats/go-multiaddr"

	"github.com/webmeshproj/webmesh/pkg/cmd/config"
	"github.com/webmeshproj/webmesh/pkg/embed"
)

func main() {
	host1 := runHost1()
	host2 := runHost2()

	defer host1.Close()
	defer host2.Close()

	ctx := context.Background()

	host1.SetStreamHandler("/echo/1.0.0", func(stream network.Stream) {
		defer stream.Close()
		fmt.Println("hello")
	})

	host1.Peerstore().AddAddrs(host2.ID(), host2.Addrs(), peerstore.PermanentAddrTTL)
	host2.Peerstore().AddAddrs(host1.ID(), host1.Addrs(), peerstore.PermanentAddrTTL)
	stream, err := host2.NewStream(ctx, host1.ID(), "/echo/1.0.0")
	if err != nil {
		log.Println("ERROR: ", err)
	} else {
		defer stream.Close()
	}
}

func runHost1() host.Host {
	conf := config.NewInsecureConfig("")
	// conf.Global.LogLevel = "info"
	conf.Bootstrap.Enabled = true
	conf.WireGuard.InterfaceName = "webmesh1"
	host, err := libp2p.New(
		embed.WithWebmeshTransport(conf),
		libp2p.ListenAddrs(
			multiaddr.StringCast("/webmesh/server.webmesh.internal/tcp/8080"),
		),
	)
	if err != nil {
		panic(err)
	}
	return host
}

func runHost2() host.Host {
	conf := config.NewInsecureConfig("")
	// conf.Global.LogLevel = "info"
	conf.Mesh.JoinAddress = "localhost:8443"
	conf.Services.API.Disabled = true
	conf.WireGuard.ListenPort = 51821
	conf.WireGuard.InterfaceName = "webmesh2"
	host, err := libp2p.New(
		embed.WithWebmeshTransport(conf),
		libp2p.ListenAddrs(
			multiaddr.StringCast("/webmesh/client.webmesh.internal/tcp/8081"),
		),
	)
	if err != nil {
		panic(err)
	}
	return host
}
