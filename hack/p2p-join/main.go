package main

import (
	"bufio"
	"context"
	"os"

	"golang.org/x/exp/slog"

	"github.com/webmeshproj/webmesh/pkg/campfire"
)

var (
	log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
)

func main() {
	slog.SetDefault(log)
	ctx := context.Background()
	cf, err := campfire.Join(ctx, campfire.Options{
		PSK: []byte("EsgoxE7TmwXJTsSzdcLaQxjVcpimv0a0"),
	})
	if err != nil {
		panic(err)
	}
	defer cf.Close()
	select {
	case <-ctx.Done():
	case <-cf.Ready():
	case err := <-cf.Errors():
		log.Error("error", "error", err.Error())
	}
	for {
		conn, err := cf.Accept()
		if err != nil {
			panic(err)
		}
		log.Info("accepted connection")
		go func() {
			defer conn.Close()
			r := bufio.NewReader(conn)
			for {
				line, err := r.ReadBytes('\n')
				if err != nil {
					log.Error("read error", "error", err.Error())
					return
				}
				log.Info("read line", "line", string(line))
			}
		}()
		stdin := bufio.NewReader(os.Stdin)
		for {
			line, err := stdin.ReadBytes('\n')
			if err != nil {
				log.Error("read error", "error", err.Error())
				return
			}
			log.Info("read line", "line", string(line))
			if _, err := conn.Write(line); err != nil {
				log.Error("write error", "error", err.Error())
				return
			}
		}
	}
}
