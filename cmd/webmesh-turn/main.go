package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/webmeshproj/webmesh/pkg/net/endpoints"
	"github.com/webmeshproj/webmesh/pkg/services/turn"
	"github.com/webmeshproj/webmesh/pkg/util"
	"github.com/webmeshproj/webmesh/pkg/version"
)

func main() {
	var (
		publicIP        string
		relayAddressUDP string
		listenUDP       string
		realm           string
		portRange       string
		logLevel        string
		enableCampfire  bool
		detectPublicIP  bool
	)
	flag.StringVar(&publicIP, "public-ip", "127.0.0.1", "Public IP address to advertise for TURN relaying")
	flag.StringVar(&relayAddressUDP, "relay-address-udp", "0.0.0.0", "The address to bind to for UDP relay traffic")
	flag.StringVar(&listenUDP, "listen-udp", ":3478", "The address to listen on for UDP traffic")
	flag.StringVar(&realm, "realm", "localhost", "The realm to use for the TURN server")
	flag.StringVar(&portRange, "port-range", "49152-65535", "The port range to use for TURN relaying")
	flag.BoolVar(&enableCampfire, "enable-campfire", false, "Enable Campfire protocol extensions")
	flag.BoolVar(&detectPublicIP, "detect-public-ip", false, "Detect public IP address automatically")
	flag.StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	flag.Parse()

	util.SetupLogging(logLevel)

	if detectPublicIP {
		endpoints, err := endpoints.Detect(context.Background(), endpoints.DetectOpts{
			AllowRemoteDetection: true,
		})
		if err != nil {
			fatal(err)
		}
		if len(endpoints) == 0 {
			fatal(errors.New("could not detect any endpoints"))
		}
		publicIP = endpoints[0].Addr().String()
	}

	opts := turn.Options{
		PublicIP:        publicIP,
		RelayAddressUDP: relayAddressUDP,
		ListenUDP:       listenUDP,
		Realm:           realm,
		PortRange:       portRange,
		EnableCampfire:  enableCampfire,
	}
	slog.Default().Info("Starting TURN server",
		slog.Any("opts", opts),
		slog.String("version", version.Version),
		slog.String("commit", version.Commit),
		slog.String("buildDate", version.BuildDate),
	)
	server, err := turn.NewServer(&opts)
	if err != nil {
		fatal(err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	slog.Default().Info("Shutting down...")
	if err := server.Close(); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	slog.Default().Error(err.Error())
	os.Exit(1)
}
