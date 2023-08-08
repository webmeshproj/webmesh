package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/webmeshproj/webmesh/pkg/mesh"
	"github.com/webmeshproj/webmesh/pkg/services/campfire"
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
	mesh, err := mesh.NewTestMesh(context.Background())
	if err != nil {
		panic(err)
	}
	server := campfire.NewServer(mesh, &campfire.Options{
		ListenUDP: ":4095",
	})
	if err := server.ListenAndServe(context.Background()); err != nil {
		panic(err)
	}
}
