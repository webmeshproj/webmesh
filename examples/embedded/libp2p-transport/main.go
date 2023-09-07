package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	dutil "github.com/libp2p/go-libp2p/p2p/discovery/util"
	libp2pquic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	libp2ptcp "github.com/libp2p/go-libp2p/p2p/transport/tcp"
	"github.com/multiformats/go-multiaddr"

	"github.com/webmeshproj/webmesh/pkg/cmd/config"
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/embed"
	"github.com/webmeshproj/webmesh/pkg/net/endpoints"
	wlibp2p "github.com/webmeshproj/webmesh/pkg/net/transport/libp2p"
)

func main() {
	quicTest := flag.Bool("quic", false, "use QUIC transport")
	webmeshTest := flag.Bool("webmesh", false, "use WebMesh transport")
	tcpTest := flag.Bool("tcp", false, "use TCP transport")
	payloadSize := flag.Int("payload", 4096, "payload size")
	logLevel := flag.String("loglevel", "", "log level")
	join := flag.String("join", "", "rendezvous string to join")
	flag.Parse()

	if !*quicTest && !*webmeshTest && !*tcpTest {
		log.Println("No transport specified, defaulting to TCP")
		*tcpTest = true
	}

	var rendezvous string
	if len(flag.Args()) > 0 {
		rendezvous = flag.Args()[0]
	}

	mode := "server"
	if rendezvous != "" {
		mode = "client"
	} else {
		rendezvous = string(crypto.MustGeneratePSK())
	}

	var opts libp2p.Option
	if *quicTest {
		opts = libp2p.ChainOptions(libp2p.Transport(libp2pquic.NewTransport), libp2p.DefaultListenAddrs)
	} else if *tcpTest {
		opts = libp2p.ChainOptions(libp2p.Transport(libp2ptcp.NewTCPTransport), libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	} else if *webmeshTest {
		if mode == "server" {
			joinRendezvous := string(crypto.MustGeneratePSK())
			log.Println("Webmesh Joining rendezvous:", joinRendezvous)
			opts = newWebmeshServerOptions(joinRendezvous, *logLevel)
		} else {
			opts = newWebmeshClientOptions(*join, *logLevel)
		}
	}

	var err error
	switch mode {
	case "server":
		err = runServer(rendezvous, *payloadSize, opts)
	case "client":
		err = runClient(rendezvous, *payloadSize, opts)
	}
	if err != nil {
		panic(err)
	}
}

func runServer(rendezvous string, payloadSize int, opts libp2p.Option) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	log.Println("Setting up host")
	host, err := libp2p.New(opts)
	if err != nil {
		return err
	}
	defer host.Close()
	log.Println("Bootstrapping the DHT")
	dhtctx, dhtcancel := context.WithTimeout(ctx, time.Second*10)
	defer dhtcancel()
	dht, err := wlibp2p.NewDHT(dhtctx, host, []multiaddr.Multiaddr{}, time.Second*2)
	if err != nil {
		return err
	}
	defer dht.Close()
	log.Println("DHT bootstrap complete")

	routingDiscovery := drouting.NewRoutingDiscovery(dht)
	dutil.Advertise(ctx, routingDiscovery, rendezvous)
	log.Println("Listening for libp2p connections at rendezvous:", rendezvous)
	host.SetStreamHandler("/echo/1.0.0", func(stream network.Stream) {
		log.Printf("Client connected on %s, streaming echo\n", stream.Conn().RemoteMultiaddr())
		runSpeedTest(ctx, stream, payloadSize)
	})

	<-sig
	return nil
}

func runClient(rendezvous string, payloadSize int, opts libp2p.Option) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	log.Println("Setting up host")
	host, err := libp2p.New(opts)
	if err != nil {
		return err
	}
	defer host.Close()
	log.Println("Bootstrapping the DHT")
	dhtctx, dhtcancel := context.WithTimeout(ctx, time.Second*10)
	defer dhtcancel()
	dht, err := wlibp2p.NewDHT(dhtctx, host, []multiaddr.Multiaddr{}, time.Second*2)
	if err != nil {
		return err
	}
	defer dht.Close()
	log.Println("DHT bootstrap complete")
	log.Println("Searching DHT for peer node")
	routingDiscovery := drouting.NewRoutingDiscovery(dht)
	peerChan, err := routingDiscovery.FindPeers(ctx, rendezvous)
	if err != nil {
		return err
	}
	for {
		select {
		case <-sig:
			return nil
		case <-ctx.Done():
			return nil
		case peer := <-peerChan:
			if peer.ID == host.ID() {
				continue
			}
			stream, err := host.NewStream(context.Background(), peer.ID, "/echo/1.0.0")
			if err != nil {
				continue
			}
			defer stream.Close()
			log.Printf("Connected to server %s, streaming echo\n", stream.Conn().RemoteMultiaddr())
			runSpeedTest(ctx, stream, payloadSize)
			return nil
		}
	}
}

func runSpeedTest(ctx context.Context, stream network.Stream, payloadSize int) {
	var bytesWritten atomic.Int64
	var bytesRead atomic.Int64
	start := time.Now()
	go func() {
		for range time.NewTicker(time.Second).C {
			written := bytesWritten.Load()
			read := bytesRead.Load()
			elapsed := time.Since(start)
			log.Printf("Sent %d bytes in %s (%.2f MB/s)", written, elapsed, float64(written)/elapsed.Seconds()/1024/1024)
			log.Printf("Received %d bytes in %s (%.2f MB/s)", read, elapsed, float64(read)/elapsed.Seconds()/1024/1024)
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
	log.Println("Setting up webmesh transport")
	conf := config.NewInsecureConfig("client")
	conf.Global.LogLevel = loglevel
	conf.Discovery.Discover = true
	conf.Discovery.PSK = rendezvous
	conf.Discovery.ConnectTimeout = time.Second * 2
	conf.Services.API.Disabled = true
	conf.WireGuard.ListenPort = 51821
	conf.WireGuard.InterfaceName = "webmeshclient0"
	return libp2p.ChainOptions(
		embed.WithWebmeshTransport(conf),
		libp2p.ListenAddrs(
			multiaddr.StringCast("/webmesh/client.webmesh.internal/tcp/0"),
			multiaddr.StringCast("/webmesh/client.webmesh.internal/udp/0/quic"),
		),
	)
}

func newWebmeshServerOptions(rendezvous string, loglevel string) libp2p.Option {
	log.Println("Setting up webmesh transport")
	eps, err := endpoints.Detect(context.Background(), endpoints.DetectOpts{
		DetectPrivate: true,
	})
	if err != nil {
		panic(err)
	}
	conf := config.NewInsecureConfig("server")
	conf.Global.LogLevel = loglevel
	conf.Discovery.Announce = true
	conf.Discovery.PSK = rendezvous
	conf.Discovery.ConnectTimeout = time.Second * 2
	conf.Mesh.PrimaryEndpoint = eps[0].Addr().String()
	conf.Bootstrap.Enabled = true
	conf.WireGuard.InterfaceName = "webmeshserver0"
	conf.WireGuard.ListenPort = 51820
	return libp2p.ChainOptions(
		embed.WithWebmeshTransport(conf),
		libp2p.ListenAddrs(
			multiaddr.StringCast("/webmesh/server.webmesh.internal/tcp/0"),
			multiaddr.StringCast("/webmesh/server.webmesh.internal/udp/0/quic"),
		),
	)
}
