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
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"

	"github.com/webmeshproj/webmesh/pkg/config"
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
	log.Println("Listening for libp2p connections on:")
	for _, addr := range host.Addrs() {
		log.Println("\t-", addr)
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
