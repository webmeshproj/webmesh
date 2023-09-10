package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	dutil "github.com/libp2p/go-libp2p/p2p/discovery/util"
	"github.com/multiformats/go-multiaddr"

	"github.com/webmeshproj/webmesh/pkg/config"
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/embed"
	wmp2p "github.com/webmeshproj/webmesh/pkg/net/transport/libp2p"
)

func main() {
	quic := flag.Bool("quic", false, "use QUIC transport")
	payloadSize := flag.Int("payload", 4096, "payload size")
	logLevel := flag.String("loglevel", "", "log level")
	flag.Parse()

	mode := "server"
	rendezvous := string(crypto.MustGeneratePSK())
	if len(flag.Args()) >= 1 {
		mode = "client"
		rendezvous = flag.Args()[0]
	}

	if *quic {
		runQUICTest(mode, rendezvous, *payloadSize)
		return
	}

	var opts libp2p.Option
	if mode == "server" {
		log.Println("Webmesh Joining rendezvous:", rendezvous)
		opts = newWebmeshServerOptions(rendezvous, *logLevel)
	} else {
		opts = newWebmeshClientOptions(rendezvous, *logLevel)
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
	log.Println("Payload size:", prettyByteSize(float64(payloadSize)))
	host, err := libp2p.New(opts)
	if err != nil {
		return err
	}
	defer host.Close()
	log.Println("Listening for libp2p connections on:")
	for _, addr := range host.Addrs() {
		log.Println("\t-", addr)
	}
	host.SetStreamHandler("/speedtest", func(stream network.Stream) {
		log.Println("Received connection from", stream.Conn().RemoteMultiaddr())
		go func() {
			defer cancel()
			runSpeedTest(ctx, stream, payloadSize)
		}()
	})
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	select {
	case <-ctx.Done():
	case <-sig:
	}
	return nil
}

func runClient(payloadSize int, opts libp2p.Option) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log.Println("Setting up libp2p host and webmesh node")
	log.Println("Payload size:", prettyByteSize(float64(payloadSize)))
	host, err := libp2p.New(opts)
	if err != nil {
		return err
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
	log.Println("Dialing peer:", toDial)
	conn, err := host.NewStream(ctx, toDial, "/speedtest")
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

func runQUICTest(mode string, rendezvous string, payloadSize int) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	host, err := libp2p.New(libp2p.ListenAddrStrings("/ip6/::/udp/0/quic-v1"), libp2p.FallbackDefaults)
	if err != nil {
		panic(err)
	}
	defer host.Close()
	dht, err := wmp2p.NewDHT(ctx, host, nil, time.Second*3)
	if err != nil {
		panic(err)
	}
	routingDiscovery := drouting.NewRoutingDiscovery(dht)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	log.Println("Payload size:", prettyByteSize(float64(payloadSize)))
	if mode == "server" {
		dutil.Advertise(ctx, routingDiscovery, rendezvous, discovery.TTL(time.Minute))
		log.Println("Advertised our PSK:", rendezvous)
		log.Println("Listening for libp2p connections on:")
		for _, addr := range host.Addrs() {
			log.Println("\t-", addr)
		}
		host.SetStreamHandler("/speedtest", func(stream network.Stream) {
			log.Println("Received connection from", stream.Conn().RemoteMultiaddr())
			go func() {
				defer cancel()
				runSpeedTest(ctx, stream, payloadSize)
			}()
		})
		select {
		case <-ctx.Done():
		case <-sig:
		}
		return
	}
	log.Println("Searching for peers on the DHT with our PSK", rendezvous)
	peerChan, err := routingDiscovery.FindPeers(ctx, rendezvous)
	if err != nil {
		panic(err)
	}
	log.Println("Waiting for a peer to connect to")
	for peer := range peerChan {
		if peer.ID == host.ID() {
			continue
		}
		log.Println("Dialing peer:", peer.ID)
		conn, err := host.NewStream(ctx, peer.ID, "/speedtest")
		if err != nil {
			log.Println("Failed to dial peer:", err)
			continue
		}
		log.Println("Opened connection to", conn.Conn().RemoteMultiaddr())
		go runSpeedTest(ctx, conn, payloadSize)
		select {
		case <-ctx.Done():
		case <-sig:
		}
		return
	}
}

func runSpeedTest(ctx context.Context, stream network.Stream, payloadSize int) {
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
				sent := prettyByteSize(float64(written) / elapsed.Seconds())
				received := prettyByteSize(float64(read) / elapsed.Seconds())
				fmt.Printf("Sent %d bytes in %s (%s/s)\n", written, elapsed, sent)
				fmt.Printf("Received %d bytes in %s (%s/s)\n", read, elapsed, received)
			}
		}
	}()
	go func() {
		defer cancel()
		buf := make([]byte, payloadSize)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				n, err := stream.Write(buf)
				if err != nil {
					if !errors.Is(err, net.ErrClosed) {
						log.Println("ERROR: ", err)
					}
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
			err := stream.SetReadDeadline(time.Now().Add(time.Second))
			if err != nil {
				if !errors.Is(err, io.EOF) {
					log.Println("ERROR: ", err)
				}
				return
			}
			n, err := stream.Read(buf)
			if err != nil {
				// Check if it's a network timeout error
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				if !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
					log.Println("ERROR: ", err)
				}
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
	return embed.WithWebmeshTransport(embed.TransportOptions{
		Config:     conf,
		Rendezvous: rendezvous,
		Laddrs:     []multiaddr.Multiaddr{multiaddr.StringCast("/ip6/::/tcp/0")},
		LogLevel:   loglevel,
	})
}

func prettyByteSize(b float64) string {
	for _, unit := range []string{"", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"} {
		if math.Abs(b) < 1024.0 {
			return fmt.Sprintf("%3.1f%sB", b, unit)
		}
		b /= 1024.0
	}
	return fmt.Sprintf("%.1fYiB", b)
}
