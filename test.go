package main

import (
	"context"
	"os"

	"golang.org/x/exp/slog"

	"github.com/webmeshproj/webmesh/pkg/campfire"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	slog.SetDefault(log)
	ctx := context.Background()
	cf, err := campfire.New(ctx, campfire.Options{
		PSK: []byte("E7gonE7TmwXJTaSzEkLqQx0Vcpimv0a0"),
	})
	if err != nil {
		panic(err)
	}
	defer cf.Close()
	select {
	case err := <-cf.Errors():
		panic(err)
	case <-cf.Ready():
	case <-ctx.Done():
	}
	// We'd have a bidirection stream here.
}
