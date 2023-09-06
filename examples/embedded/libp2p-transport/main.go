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
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"

	"github.com/webmeshproj/webmesh/pkg/cmd/config"
	"github.com/webmeshproj/webmesh/pkg/embed"
	"github.com/webmeshproj/webmesh/pkg/net/endpoints"
)

func main() {
	payloadSize := flag.Int("payload", 1024, "payload size")
	join := flag.String("join", "", "join address")
	flag.Parse()

	mode := "server"
	if *join != "" {
		mode = "client"
	}

	var err error
	switch mode {
	case "server":
		err = runServer(*payloadSize)
	case "client":
		err = runClient(*join, *payloadSize)
	}
	if err != nil {
		panic(err)
	}
}

func runServer(payloadSize int) error {
	log.Println("Setting up webmesh transport")
	eps, err := endpoints.Detect(context.Background(), endpoints.DetectOpts{
		DetectPrivate: true,
	})
	if err != nil {
		return err
	}
	conf := config.NewInsecureConfig("server")
	conf.Mesh.PrimaryEndpoint = eps[0].Addr().String()
	conf.Bootstrap.Enabled = true
	conf.WireGuard.InterfaceName = "webmeshserver0"
	conf.WireGuard.ListenPort = 51820
	host, err := libp2p.New(
		embed.WithWebmeshTransport(conf),
		libp2p.ListenAddrs(
			multiaddr.StringCast("/webmesh/server.webmesh.internal/tcp/0"),
		),
	)
	if err != nil {
		return err
	}
	defer host.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	var bytesWritten atomic.Int64
	var bytesRead atomic.Int64
	start := time.Now()

	log.Println("Listening for libp2p connections")
	host.SetStreamHandler("/echo/1.0.0", func(stream network.Stream) {
		log.Println("Client connected, streaming echo")
		defer stream.Close()
		go func() {
			for range time.NewTicker(time.Second).C {
				written := bytesWritten.Swap(0)
				read := bytesRead.Swap(0)
				elapsed := time.Since(start)
				log.Printf("Sent %d bytes in %s (%.2f MB/s)", written, elapsed, float64(written)/elapsed.Seconds()/1024/1024)
				log.Printf("Received %d bytes in %s (%.2f MB/s)", read, elapsed, float64(read)/elapsed.Seconds()/1024/1024)
			}
		}()
		go func() {
			for {
				select {
				case <-sig:
					return
				default:
					n, err := stream.Read(make([]byte, payloadSize))
					if err != nil {
						log.Println("ERROR: ", err)
						return
					}
					bytesRead.Add(int64(n))
				}
			}
		}()
		payload := make([]byte, payloadSize)
		for {
			select {
			case <-sig:
				return
			default:
				n, err := stream.Write(payload)
				if err != nil {
					log.Println("ERROR: ", err)
					return
				}
				bytesWritten.Add(int64(n))
			}
		}
	})

	<-sig
	return nil
}

func runClient(joinAddress string, payloadSize int) error {
	log.Println("Setting up webmesh transport")
	conf := config.NewInsecureConfig("client")
	conf.Mesh.JoinAddress = joinAddress
	conf.Services.API.Disabled = true
	conf.WireGuard.ListenPort = 51821
	conf.WireGuard.InterfaceName = "webmeshclient0"
	host, err := libp2p.New(
		embed.WithWebmeshTransport(conf),
		libp2p.ListenAddrs(
			multiaddr.StringCast("/webmesh/client.webmesh.internal/tcp/0"),
		),
	)
	if err != nil {
		return err
	}
	defer host.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	peers := host.Peerstore().Peers()
	var server peer.ID
	for _, p := range peers {
		if p.String() != host.ID().String() {
			server = p
			break
		}
	}
	log.Println("Dialing server node")
	stream, err := host.NewStream(context.Background(), server, "/echo/1.0.0")
	if err != nil {
		return err
	}
	defer stream.Close()
	log.Println("Connected to server, streaming echo")

	var bytesWritten atomic.Int64
	var bytesRead atomic.Int64
	start := time.Now()

	go func() {
		for range time.NewTicker(time.Second).C {
			written := bytesWritten.Swap(0)
			read := bytesRead.Swap(0)
			elapsed := time.Since(start)
			log.Printf("Sent %d bytes in %s (%.2f MB/s)", written, elapsed, float64(written)/elapsed.Seconds()/1024/1024)
			log.Printf("Received %d bytes in %s (%.2f MB/s)", read, elapsed, float64(read)/elapsed.Seconds()/1024/1024)
		}
	}()

	payload := make([]byte, payloadSize)
	go func() {
		for {
			select {
			case <-sig:
				return
			default:
				n, err := stream.Write(payload)
				if err != nil {
					log.Println("ERROR: ", err)
					return
				}
				bytesWritten.Add(int64(n))
			}
		}
	}()
	for {
		select {
		case <-sig:
			return nil
		default:
			n, err := stream.Read(make([]byte, payloadSize))
			if err != nil {
				log.Println("ERROR: ", err)
				return err
			}
			bytesRead.Add(int64(n))
		}
	}
}
