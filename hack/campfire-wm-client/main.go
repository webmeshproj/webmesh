package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/webmeshproj/webmesh/pkg/services/campfire"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:4095", "address to connect to")
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
	cf, err := campfire.NewClient(*addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err.Error())
		os.Exit(1)
	}

	go func() {
		for msg := range cf.Messages() {
			fmt.Fprintf(os.Stderr, "message: %+v\n", msg)
			fmt.Fprintf(os.Stderr, "> ")
		}
	}()

	in := bufio.NewScanner(os.Stdin)
	fmt.Fprintf(os.Stderr, "> ")
	for in.Scan() {
		text := in.Text()
		if text == "" {
			continue
		}
		fields := strings.Fields(text)
		switch fields[0] {
		case "join":
			if len(fields) < 2 {
				fmt.Fprintln(os.Stderr, "ERROR: join <room>")
				goto Next
			}
			if err := cf.Join(context.Background(), fields[1]); err != nil {
				fmt.Fprintln(os.Stderr, "ERROR:", err.Error())
				goto Next
			}
			fmt.Fprintln(os.Stderr, "joined room", fields[1])
		case "leave":
			if len(fields) < 2 {
				fmt.Fprintln(os.Stderr, "ERROR: leave <room>")
				goto Next
			}
			if err := cf.Leave(context.Background(), fields[1]); err != nil {
				fmt.Fprintln(os.Stderr, "ERROR:", err.Error())
				goto Next
			}
			fmt.Fprintln(os.Stderr, "left room", fields[1])
		case "msg":
			if len(fields) < 3 {
				fmt.Fprintln(os.Stderr, "ERROR: msg <room> <message>")
				goto Next
			}
			if err := cf.Send(context.Background(), fields[1], "", strings.Join(fields[2:], " ")); err != nil {
				fmt.Fprintln(os.Stderr, "ERROR:", err.Error())
				goto Next
			}
		case "send":
			if len(fields) < 4 {
				fmt.Fprintln(os.Stderr, "ERROR: send <room> <to> <message>")
				goto Next
			}
			if err := cf.Send(context.Background(), fields[1], fields[2], strings.Join(fields[3:], " ")); err != nil {
				fmt.Fprintln(os.Stderr, "ERROR:", err.Error())
				goto Next
			}
		case "list":
			if len(fields) < 2 {
				fmt.Fprintln(os.Stderr, "ERROR: list <room>")
				goto Next
			}
			members, err := cf.List(context.Background(), fields[1])
			if err != nil {
				fmt.Fprintln(os.Stderr, "ERROR:", err.Error())
				goto Next
			}
			fmt.Fprintln(os.Stderr, "members of room", fields[1])
			for _, member := range members {
				fmt.Fprintln(os.Stderr, "  ", member)
			}
		case "help":
			fmt.Fprintln(os.Stderr, "commands:")
			fmt.Fprintln(os.Stderr, "  join <room>")
			fmt.Fprintln(os.Stderr, "  leave <room>")
			fmt.Fprintln(os.Stderr, "  msg <room> <message>")
			fmt.Fprintln(os.Stderr, "  send <room> <to> <message>")
			fmt.Fprintln(os.Stderr, "  list <room>")
			fmt.Fprintln(os.Stderr, "  exit")
		case "exit":
			cf.Close(context.Background())
			os.Exit(0)
		}
	Next:
		fmt.Fprintf(os.Stderr, "> ")
	}
}
