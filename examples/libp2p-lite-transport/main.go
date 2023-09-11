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
	"runtime/debug"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/network"
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	dutil "github.com/libp2p/go-libp2p/p2p/discovery/util"

	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/embed"
	"github.com/webmeshproj/webmesh/pkg/embed/transport"
	"github.com/webmeshproj/webmesh/pkg/net/endpoints"
	"github.com/webmeshproj/webmesh/pkg/net/system"
	wmp2p "github.com/webmeshproj/webmesh/pkg/net/transport/libp2p"
	"github.com/webmeshproj/webmesh/pkg/net/wireguard"
	"github.com/webmeshproj/webmesh/pkg/util/logutil"
)

func main() {
	quic := flag.Bool("quic", false, "use QUIC transport")
	payloadSize := flag.Int("payload", 4096, "payload size")
	wireguardPort := flag.Int("wgport", wireguard.DefaultListenPort, "wireguard port")
	ifaceName := flag.String("ifname", wireguard.DefaultInterfaceName, "wireguard interface name")
	mtu := flag.Int("mtu", system.DefaultMTU, "wireguard interface MTU")
	logLevel := flag.String("loglevel", "error", "log level")
	flag.Parse()

	mode := "server"
	rendezvous := string(crypto.MustGeneratePSK())
	if len(flag.Args()) >= 1 {
		mode = "client"
		rendezvous = flag.Args()[0]
	}
	log.Println("Discover rendezvous string:", rendezvous)

	var opts libp2p.Option
	switch *quic {
	case true:
		opts = libp2p.ChainOptions(
			libp2p.ListenAddrStrings("/ip6/::/udp/0/quic-v1"),
			libp2p.FallbackDefaults,
		)
	case false:
		opts = libp2p.ChainOptions(
			embed.WithLiteWebmeshTransport(transport.LiteOptions{
				Config: transport.WireGuardOptions{
					ListenPort:         uint16(*wireguardPort),
					InterfaceName:      *ifaceName,
					ForceInterfaceName: true,
					MTU:                *mtu,
				},
				EndpointDetection: &endpoints.DetectOpts{
					DetectIPv6:    true,
					DetectPrivate: true,
				},
				Logger: logutil.NewLogger(*logLevel),
			}),
			libp2p.FallbackDefaults,
		)
	}

	var err error
	switch mode {
	case "server":
		err = runServer(*payloadSize, opts, rendezvous)
	case "client":
		err = runClient(*payloadSize, opts, rendezvous)
	}
	if err != nil {
		debug.PrintStack()
		log.Println("ERROR:", err.Error())
	}
}

func runServer(payloadSize int, opts libp2p.Option, rendezvous string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log.Println("Setting up libp2p host")
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
	dht, err := wmp2p.NewDHT(ctx, host, nil, time.Second*3)
	if err != nil {
		return err
	}
	defer dht.Close()
	routingDiscovery := drouting.NewRoutingDiscovery(dht)
	dutil.Advertise(ctx, routingDiscovery, rendezvous, discovery.TTL(time.Minute))
	log.Println("Advertised our PSK:", rendezvous)
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

func runClient(payloadSize int, opts libp2p.Option, rendezvous string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log.Println("Setting up libp2p host")
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
	dht, err := wmp2p.NewDHT(ctx, host, nil, time.Second*3)
	if err != nil {
		return err
	}
	defer dht.Close()

	routingDiscovery := drouting.NewRoutingDiscovery(dht)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	log.Println("Searching for peers on the DHT with our PSK", rendezvous)
FindPeers:
	for {
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
			case peer, ok := <-peerChan:
				if !ok {
					continue FindPeers
				}
				if peer.ID == host.ID() {
					continue
				}
				log.Println("Found peer:", peer.ID)
				for _, addr := range peer.Addrs {
					log.Println("\t-", addr)
				}
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
				return nil
			}
		}
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

func prettyByteSize(b float64) string {
	for _, unit := range []string{"", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"} {
		if math.Abs(b) < 1024.0 {
			return fmt.Sprintf("%3.1f%sB", b, unit)
		}
		b /= 1024.0
	}
	return fmt.Sprintf("%.1fYiB", b)
}
