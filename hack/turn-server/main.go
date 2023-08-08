package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/webmeshproj/webmesh/pkg/services/turn"
)

func main() {
	logLevel := flag.String("log-level", "info", "log level")
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: func() slog.Level {
			switch strings.ToLower(*logLevel) {
			case "debug":
				return slog.LevelDebug
			case "info":
				return slog.LevelInfo
			case "warn":
				return slog.LevelWarn
			case "error":
				return slog.LevelError
			default:
				fmt.Fprintln(os.Stderr, "invalid log level")
				os.Exit(1)
			}
			return slog.LevelInfo
		}(),
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
