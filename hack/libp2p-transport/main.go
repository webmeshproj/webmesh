package main

import (
	"context"
	"fmt"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/multiformats/go-multiaddr"

	"github.com/webmeshproj/webmesh/pkg/cmd/config"
	"github.com/webmeshproj/webmesh/pkg/embed"
)

func main() {
	host1, err := runHost1()
	if err != nil {
		panic(err)
	}
	host2, err := runHost2()
	if err != nil {
		host1.Close()
		panic(err)
	}
	defer host1.Close()
	defer host2.Close()
	host1.SetStreamHandler("/echo/1.0.0", func(stream network.Stream) {
		defer stream.Close()
		fmt.Println("hello")
	})
	stream, err := host2.NewStream(context.Background(), host1.ID(), "/echo/1.0.0")
	if err != nil {
		fmt.Println("ERROR: ", err)
	} else {
		defer stream.Close()
	}
}

func runHost1() (host.Host, error) {
	conf := config.NewInsecureConfig("server")
	conf.Bootstrap.Enabled = true
	conf.WireGuard.InterfaceName = "webmesh1"
	host, err := libp2p.New(
		embed.WithWebmeshTransport(conf),
		libp2p.ListenAddrs(
			multiaddr.StringCast("/webmesh//tcp/0"),
		),
	)
	if err != nil {
		return nil, err
	}
	return host, nil
}

func runHost2() (host.Host, error) {
	conf := config.NewInsecureConfig("client")
	conf.Mesh.JoinAddress = "localhost:8443"
	conf.Services.API.Disabled = true
	conf.WireGuard.ListenPort = 51821
	conf.WireGuard.InterfaceName = "webmesh2"
	host, err := libp2p.New(
		embed.WithWebmeshTransport(conf),
		libp2p.ListenAddrs(
			multiaddr.StringCast("/webmesh//tcp/0"),
		),
	)
	if err != nil {
		return nil, err
	}
	return host, nil
}
