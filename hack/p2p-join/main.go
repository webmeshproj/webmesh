package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
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
	cf, err := campfire.Join(ctx, campfire.Options{
		PSK: []byte(*psk),
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	defer cf.Close()
WaitForReady:
	for {
		select {
		case <-ctx.Done():
			log.Error("error", "error", ctx.Err().Error())
			return
		case err := <-cf.Errors():
			log.Error("error", "error", err.Error())
		case <-cf.Ready():
			break WaitForReady
		}
	}
	for {
		conn, err := cf.Accept()
		if err != nil {
			fmt.Fprint(os.Stderr, "Error accepting connection:", err.Error())
			os.Exit(1)
		}
		log.Info("Established WebRTC connection")
		go func() {
			defer conn.Close()
			r := bufio.NewReader(conn)
			for {
				line, err := r.ReadBytes('\n')
				if err != nil {
					log.Error("read error", "error", err.Error())
					return
				}
				fmt.Print(string(line))
				fmt.Fprint(os.Stdin, "> ")
			}
		}()
		stdin := bufio.NewReader(os.Stdin)
		for {
			fmt.Fprint(os.Stdin, "> ")
			line, err := stdin.ReadBytes('\n')
			if err != nil {
				log.Error("read error", "error", err.Error())
				return
			}
			if _, err := conn.Write(line); err != nil {
				log.Error("write error", "error", err.Error())
				return
			}
		}
	}
}
