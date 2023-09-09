package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"log"
	"os"
	"os/signal"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"

	"github.com/webmeshproj/webmesh/pkg/cmd/config"
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/embed"
)

func main() {
	payloadSize := flag.Int("payload", 4096, "payload size")
	logLevel := flag.String("loglevel", "", "log level")
	flag.Parse()

	mode := "server"
	if len(flag.Args()) >= 1 {
		mode = "client"
	}
	var opts libp2p.Option
	if mode == "server" {
		joinRendezvous := string(crypto.MustGeneratePSK())
		log.Println("Webmesh Joining rendezvous:", joinRendezvous)
		opts = newWebmeshServerOptions(joinRendezvous, *logLevel)
	} else {
		opts = newWebmeshClientOptions(flag.Args()[0], *logLevel)
	}

	var err error
	switch mode {
	case "server":
		err = runServer(*payloadSize, opts)
	case "client":
		err = runClient(*payloadSize, opts)
	}
	if err != nil {
		panic(err)
	}
}

func runServer(payloadSize int, opts libp2p.Option) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log.Println("Setting up libp2p host and webmesh node")
	host, err := libp2p.New(opts)
	if err != nil {
		return err
	}
	defer host.Close()
	for _, addr := range host.Addrs() {
		log.Println("Listening for libp2p connections on:", addr)
	}
	host.SetStreamHandler("", func(stream network.Stream) {
		log.Println("Received connection from", stream.Conn().RemoteMultiaddr())
		go runSpeedTest(ctx, stream, payloadSize)
	})
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
	return nil
}

func runClient(payloadSize int, opts libp2p.Option) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log.Println("Setting up libp2p host and webmesh node")
	host, err := libp2p.New(opts)
	if err != nil {
		return err
	}
	for _, addr := range host.Addrs() {
		log.Println("Listening for libp2p connections on:", addr)
	}
	defer host.Close()
	var toDial peer.ID
	for _, peer := range host.Peerstore().PeersWithAddrs() {
		if peer != host.ID() {
			log.Println("Found peer:", peer)
			log.Println("Peer addrs:", host.Peerstore().Addrs(peer))
			toDial = peer
			break
		}
	}
	if toDial == "" {
		return errors.New("no peers to dial")
	}
	conn, err := host.Network().NewStream(ctx, toDial)
	if err != nil {
		return err
	}
	defer conn.Close()
	log.Println("Opened connection to", conn.Conn().RemoteMultiaddr())
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go runSpeedTest(ctx, conn, payloadSize)
	<-sig
	return nil
}

func runSpeedTest(ctx context.Context, stream io.ReadWriteCloser, payloadSize int) {
	var bytesWritten atomic.Int64
	var bytesRead atomic.Int64
	start := time.Now()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				written := bytesWritten.Load()
				read := bytesRead.Load()
				elapsed := time.Since(start)
				log.Printf("Sent %d bytes in %s (%.2f MB/s)", written, elapsed, float64(written)/elapsed.Seconds()/1024/1024)
				log.Printf("Received %d bytes in %s (%.2f MB/s)", read, elapsed, float64(read)/elapsed.Seconds()/1024/1024)
			}
		}
	}()
	go func() {
		buf := make([]byte, payloadSize)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				n, err := stream.Write(buf)
				if err != nil {
					log.Println("ERROR: ", err)
					cancel()
					return
				}
				bytesWritten.Add(int64(n))
			}
		}
	}()
	buf := make([]byte, payloadSize)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			n, err := stream.Read(buf)
			if err != nil {
				log.Println("ERROR: ", err)
				return
			}
			bytesRead.Add(int64(n))
		}
	}
}

func newWebmeshClientOptions(rendezvous string, loglevel string) libp2p.Option {
	conf := config.NewInsecureConfig("client")
	conf.Services.API.Disabled = true
	conf.WireGuard.ListenPort = 51821
	conf.WireGuard.InterfaceName = "webmeshclient0"
	conf.WireGuard.ForceInterfaceName = true
	return embed.WithWebmeshTransport(embed.TransportOptions{
		Config:     conf,
		Rendezvous: rendezvous,
		Laddrs:     []multiaddr.Multiaddr{multiaddr.StringCast("/ip6/::/tcp/0")},
		LogLevel:   loglevel,
	})
}

func newWebmeshServerOptions(rendezvous string, loglevel string) libp2p.Option {
	conf := config.NewInsecureConfig("server")
	conf.Global.DetectEndpoints = true
	conf.Global.DetectPrivateEndpoints = true
	conf.Bootstrap.Enabled = true
	conf.WireGuard.InterfaceName = "webmeshserver0"
	conf.WireGuard.ListenPort = 51820
	conf.WireGuard.ForceInterfaceName = true
	conf.Plugins.Configs = map[string]config.PluginConfig{
		"debug": {
			Config: map[string]any{
				"enable-db-querier": true,
			},
		},
	}
	return embed.WithWebmeshTransport(embed.TransportOptions{
		Config:     conf,
		Rendezvous: rendezvous,
		Laddrs:     []multiaddr.Multiaddr{multiaddr.StringCast("/ip6/::/tcp/0")},
		LogLevel:   loglevel,
	})
}
