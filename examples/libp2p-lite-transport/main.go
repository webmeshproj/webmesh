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
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	dutil "github.com/libp2p/go-libp2p/p2p/discovery/util"

	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/embed/libp2p/protocol"
	"github.com/webmeshproj/webmesh/pkg/embed/libp2p/routing"
	"github.com/webmeshproj/webmesh/pkg/embed/libp2p/transport"
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

	var rendezvous string
	if len(flag.Args()) >= 1 {
		rendezvous = flag.Args()[0]
	}

	var opts libp2p.Option
	switch *quic {
	case true:
		opts = libp2p.ChainOptions(
			libp2p.ListenAddrStrings("/ip6/::/udp/0/quic-v1"),
			libp2p.DefaultTransports,
		)
	case false:
		transport, security, addrFactory := transport.NewLite(transport.LiteOptions{
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
		})
		opts = libp2p.ChainOptions(
			libp2p.Transport(transport),
			libp2p.ProtocolVersion(protocol.SecurityID),
			libp2p.Security(protocol.SecurityID, security),
			libp2p.AddrsFactory(addrFactory),
			libp2p.ListenAddrStrings(
				"/ip4/127.0.0.1/tcp/0/webmesh",
				"/ip6/::/tcp/0/webmesh",
				"/ip4/127.0.0.1/udp/0/quic-v1",
				"/ip6/::/udp/0/quic-v1",
			),
			libp2p.Routing(routing.PublicKeyRouter),
			libp2p.DefaultSecurity,
			libp2p.DefaultTransports,
		)
	}

	err := run(*payloadSize, opts, rendezvous)
	if err != nil {
		log.Println("ERROR:", err.Error())
	}
}

func run(payloadSize int, opts libp2p.Option, rendezvous string) error {
	var announcer bool
	if rendezvous == "" {
		// We are running in announce mode
		announcer = true
		rendezvous = string(crypto.MustGeneratePSK())
		log.Println("Discover rendezvous string:", rendezvous)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log.Println("Setting up libp2p host")
	log.Println("Payload size:", prettyByteSize(float64(payloadSize)))
	host, err := libp2p.New(opts)
	if err != nil {
		return err
	}
	defer host.Close()
	log.Println("Host ID:", host.ID())
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
	if announcer {
		dutil.Advertise(ctx, routingDiscovery, rendezvous, discovery.TTL(time.Minute))
		log.Println("Advertised our PSK:", rendezvous)
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
		return nil
	}
	log.Println("Searching for peers at our PSK", rendezvous)
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
