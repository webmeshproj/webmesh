package main

import (
	"errors"
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
	"github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/network"
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	dutil "github.com/libp2p/go-libp2p/p2p/discovery/util"
	noise "github.com/libp2p/go-libp2p/p2p/security/noise"
	tls "github.com/libp2p/go-libp2p/p2p/security/tls"
	quic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	tcp "github.com/libp2p/go-libp2p/p2p/transport/tcp"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/libp2p/config"
	"github.com/webmeshproj/webmesh/pkg/libp2p/wgtransport"
	"github.com/webmeshproj/webmesh/pkg/net/endpoints"
	"github.com/webmeshproj/webmesh/pkg/net/system"
	wmp2p "github.com/webmeshproj/webmesh/pkg/net/transport/libp2p"
	"github.com/webmeshproj/webmesh/pkg/net/wireguard"
	"github.com/webmeshproj/webmesh/pkg/util"
	"github.com/webmeshproj/webmesh/pkg/util/logutil"
)

var conf = config.Options{
	Config: config.WireGuardOptions{
		ListenPort:         wireguard.DefaultListenPort,
		InterfaceName:      wireguard.DefaultInterfaceName,
		ForceInterfaceName: true,
		MTU:                system.DefaultMTU,
	},
	EndpointDetection: &endpoints.DetectOpts{
		DetectIPv6:           true,
		DetectPrivate:        true,
		AllowRemoteDetection: false,
	},
}

var logLevel string
var payloadSize = 4096
var testType string = "webmesh"

func main() {
	// Bind flags to the configurations
	flag.IntVar(&payloadSize, "payload", payloadSize, "payload size")
	flag.IntVar(&conf.Config.ListenPort, "wgport", conf.Config.ListenPort, "wireguard port")
	flag.StringVar(&conf.Config.InterfaceName, "ifname", conf.Config.InterfaceName, "wireguard interface name")
	flag.IntVar(&conf.Config.MTU, "mtu", conf.Config.MTU, "wireguard interface MTU")
	flag.StringVar(&logLevel, "loglevel", "error", "log level")
	flag.StringVar(&testType, "type", testType, "test type")
	flag.Parse()
	conf.Logger = logutil.NewLogger(logLevel)
	err := run()
	if err != nil {
		panic(err)
	}
}

func run() error {
	var rendezvous string
	var announcer bool
	if flag.NArg() > 0 {
		rendezvous = flag.Arg(0)
	} else {
		announcer = true
		rendezvous = crypto.MustGeneratePSK().String()
	}

	var opts libp2p.Option
	switch testType {
	case "webmesh":
		log.Println("Running webmesh test")
		// opts = libp2p.ChainOptions(
		// 	libp2p.RandomIdentity,
		// 	libp2p.Transport(tcp.NewTCPTransport),
		// 	libp2p.ProtocolVersion(protocol.SecurityID),
		// 	libp2p.Security(protocol.SecurityID, wgsecurity.NewTransport(conf)),
		// 	libp2p.Muxer(protocol.SecurityID, wgsecurity.Multiplexer),
		// 	libp2p.DefaultSecurity,
		// 	libp2p.DefaultMuxers,
		// 	libp2p.DefaultListenAddrs,
		// )
		opts = libp2p.ChainOptions(
			libp2p.RandomIdentity,
			wgtransport.NewOption(logutil.NewLogger(logLevel)),
			libp2p.DefaultListenAddrs,
		)
	case "quic":
		log.Println("Running QUIC test")
		opts = libp2p.ChainOptions(
			libp2p.RandomIdentity,
			libp2p.Transport(quic.NewTransport),
			libp2p.Security(tls.ID, tls.New),
			libp2p.DefaultListenAddrs,
		)
	case "tcp":
		log.Println("Running TCP/Noise test")
		opts = libp2p.ChainOptions(
			libp2p.RandomIdentity,
			libp2p.Transport(tcp.NewTCPTransport),
			libp2p.Security(noise.ID, noise.New),
			libp2p.DefaultListenAddrs,
		)
	}

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

	// Setup the speed test handler
	ctx := context.WithLogger(context.Background(), conf.Logger)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	host.SetStreamHandler("/speedtest", func(stream network.Stream) {
		log.Println("Received connection from", stream.Conn().RemoteMultiaddr())
		go func() {
			defer cancel()
			runSpeedTest(ctx, stream, payloadSize)
		}()
	})

	dht, err := wmp2p.NewDHT(ctx, host, nil, time.Second*3)
	if err != nil {
		return err
	}
	defer dht.Close()

	// Setup signal handlers
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	// Announce or search for peers

	routingDiscovery := drouting.NewRoutingDiscovery(dht)
	if announcer {
		log.Println("Announcing for peers to connect at:", rendezvous)
		dutil.Advertise(ctx, routingDiscovery, rendezvous, discovery.TTL(time.Minute))
		select {
		case <-ctx.Done():
		case <-sig:
		}
		return nil
	}
	log.Println("Searching for peers at:", rendezvous)
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
					log.Println("Found ourself:", peer.ID)
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
				sent := util.PrettyByteSize(float64(written) / elapsed.Seconds())
				received := util.PrettyByteSize(float64(read) / elapsed.Seconds())
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
