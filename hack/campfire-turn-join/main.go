package main

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/webmeshproj/webmesh/hack/common"
	"github.com/webmeshproj/webmesh/pkg/campfire"
)

func main() {
	psk := flag.String("psk", "", "pre-shared key")
	turnServer := flag.String("turn-server", "stun:127.0.0.1:3478", "turn server")
	log := common.ParseFlagsAndSetupLogger()
	if *psk == "" {
		fmt.Fprintln(os.Stderr, "psk is required")
		os.Exit(1)
	}
	ctx := context.Background()

	conn, err := campfire.JoinTURN(ctx, campfire.Options{
		PSK:         []byte(*psk),
		TURNServers: []string{*turnServer},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	defer conn.Close()
	log.Info("got connection")
	go func() {
		defer conn.Close()
		buf := make([]byte, 1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				log.Error("error", "error", err.Error())
				return
			}
			fmt.Println("remote:", string(buf[:n]))
			fmt.Print("> ")
		}
	}()
	in := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("> ")
		line, err := in.ReadBytes('\n')
		if err != nil {
			log.Error("error", "error", err.Error())
			return
		}
		_, err = conn.Write(bytes.TrimSpace(line))
		if err != nil {
			log.Error("error", "error", err.Error())
			return
		}
	}
}
