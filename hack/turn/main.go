package main

import (
	"os"

	"github.com/webmeshproj/webmesh/pkg/services/turn"
	"golang.org/x/exp/slog"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	slog.SetDefault(log)
	srv, err := turn.NewServer(&turn.Options{
		PublicIP:         "127.0.0.1",
		ListenAddressUDP: "0.0.0.0",
		ListenPortUDP:    3478,
		PortRange:        "50000-60000",
	})
	if err != nil {
		panic(err)
	}
	defer srv.Close()
	select {}
}
