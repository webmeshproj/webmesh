package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/webmeshproj/webmesh/hack/common"
	"github.com/webmeshproj/webmesh/pkg/campfire"
)

func main() {
	psk := flag.String("psk", "", "pre-shared key")
	server := flag.String("server", "127.0.0.1:4095", "server address")
	log := common.ParseFlagsAndSetupLogger()
	ctx := context.Background()
	room, err := campfire.NewWebmeshWaitingRoom(ctx, *server, campfire.Options{
		PSK: []byte(*psk),
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	cf := campfire.JoinViaRoom(ctx, room)
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
