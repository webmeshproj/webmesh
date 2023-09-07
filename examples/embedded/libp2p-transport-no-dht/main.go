package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/multiformats/go-multiaddr"
	mnet "github.com/multiformats/go-multiaddr/net"

	"github.com/webmeshproj/webmesh/pkg/cmd/config"
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/embed"
	"github.com/webmeshproj/webmesh/pkg/net/endpoints"
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
	log.Println("Setting up host")
	host, err := libp2p.New(opts)
	if err != nil {
		return err
	}
	defer host.Close()
	var lisIP multiaddr.Multiaddr
	for _, addr := range host.Addrs() {
		if val, err := addr.ValueForProtocol(multiaddr.P_IP6); err == nil {
			lisIP = multiaddr.StringCast("/ip6/" + val)
			break
		}
	}
	l, err := mnet.Listen(multiaddr.Join(lisIP, multiaddr.StringCast("/tcp/8080")))
	if err != nil {
		return err
	}
	defer l.Close()
	log.Println("Listening for libp2p connections on", l.Multiaddr())
	conn, err := l.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	log.Println("Received connection from", conn.RemoteMultiaddr())
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go runSpeedTest(ctx, conn, payloadSize)
	<-sig
	return nil
}

func runClient(payloadSize int, opts libp2p.Option) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log.Println("Setting up host")
	host, err := libp2p.New(opts)
	if err != nil {
		return err
	}
	defer host.Close()
	var ourIP multiaddr.Multiaddr
	for _, addr := range host.Addrs() {
		if val, err := addr.ValueForProtocol(multiaddr.P_IP6); err == nil {
			ourIP = multiaddr.StringCast("/ip6/" + val)
			break
		}
	}
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network string, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "udp", "[::1]:6353")
		},
	}
	addr, err := resolver.LookupIP(ctx, "ip6", "server.webmesh.internal")
	if err != nil {
		return fmt.Errorf("failed to resolve server address: %w", err)
	}
	// We'll use the first address
	maddr, err := mnet.FromNetAddr(&net.TCPAddr{
		IP:   addr[0],
		Port: 8080,
	})
	if err != nil {
		return err
	}
	dialer := &mnet.Dialer{
		LocalAddr: multiaddr.Join(ourIP, multiaddr.StringCast("/tcp/0")),
	}
	conn, err := dialer.Dial(maddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	log.Println("Opened connection to", maddr)
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
	conf.Discovery.ConnectTimeout = time.Second
	conf.Services.API.Disabled = true
	conf.WireGuard.ListenPort = 51821
	conf.WireGuard.InterfaceName = "webmeshclient0"
	conf.WireGuard.ForceInterfaceName = true
	return libp2p.ChainOptions(
		embed.WithWebmeshTransport(conf),
		libp2p.ListenAddrs(
			multiaddr.StringCast("/webmesh/client.webmesh.internal/tcp/0"),
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
	conf.Discovery.ConnectTimeout = time.Second
	conf.Mesh.PrimaryEndpoint = eps[0].Addr().String()
	conf.Bootstrap.Enabled = true
	conf.Services.MeshDNS.Enabled = true
	conf.Services.MeshDNS.ListenUDP = "[::]:6353"
	conf.Services.MeshDNS.ListenTCP = "[::]:6353"
	conf.WireGuard.InterfaceName = "webmeshserver0"
	conf.WireGuard.ListenPort = 51820
	conf.WireGuard.ForceInterfaceName = true
	return libp2p.ChainOptions(
		embed.WithWebmeshTransport(conf),
		libp2p.ListenAddrs(
			multiaddr.StringCast("/webmesh/server.webmesh.internal/tcp/0"),
		),
	)
}
