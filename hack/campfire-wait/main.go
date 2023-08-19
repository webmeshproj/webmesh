package main

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/webmeshproj/webmesh/pkg/campfire"
	"github.com/webmeshproj/webmesh/pkg/util"
)

func main() {
	psk := flag.String("psk", "", "pre-shared key")
	turnServer := flag.String("turn-server", "stun:127.0.0.1:3478", "turn server")
	logLevel := flag.String("log-level", "info", "log level")
	flag.Parse()
	log := util.SetupLogging(*logLevel)
	if *psk == "" {
		fmt.Fprintln(os.Stderr, "psk is required")
		os.Exit(1)
	}
	ctx := context.Background()

	cf, err := campfire.Wait(ctx, campfire.Options{
		PSK:         []byte(*psk),
		TURNServers: []string{*turnServer},
		PEMFile:     "key.pem",
	})

	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	defer cf.Close()

	go func() {
		select {
		case err := <-cf.Errors():
			log.Error("error", "error", err.Error())
			os.Exit(1)
		case <-cf.Expired():
			log.Info("campfire expired")
			os.Exit(0)
		}
	}()

	fmt.Println(">>> Waiting for connections")
	conn, err := cf.Accept()
	if err != nil {
		log.Error("error", "error", err.Error())
		return
	}
	fmt.Println(">>> New peer connection")
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
