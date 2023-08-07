package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"golang.org/x/exp/slog"

	"github.com/webmeshproj/webmesh/pkg/campfire"
)

func main() {
	psk := flag.String("psk", "", "pre-shared key")
	logLevel := flag.String("log-level", "info", "log level")
	flag.Parse()
	if *psk == "" {
		fmt.Fprintln(os.Stderr, "psk is required")
		os.Exit(1)
	}
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
	ctx := context.Background()
	cf, err := campfire.NewWebmeshWaitingRoom(ctx, campfire.Options{
		PSK:         []byte(*psk),
		TURNServers: []string{"127.0.0.1:4095"},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err.Error())
		os.Exit(1)
	}
	defer cf.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	select {
	case <-sig:
	case err := <-cf.Errors():
		fmt.Fprintln(os.Stderr, "ERROR:", err.Error())
		os.Exit(1)
	}
}
