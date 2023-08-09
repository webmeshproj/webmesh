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
	log := common.ParseFlagsAndSetupLogger()
	if *psk == "" {
		fmt.Fprintln(os.Stderr, "psk is required")
		os.Exit(1)
	}
	ctx := context.Background()

	cf, err := campfire.WaitICE(ctx, campfire.Options{
		PSK: []byte(*psk),
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	defer cf.Close()

	select {
	case <-ctx.Done():
		log.Error("error", "error", ctx.Err().Error())
		return
	case err := <-cf.Errors():
		log.Error("error", "error", err.Error())
		return
	case <-cf.Ready():
	}

	for {
		log.Info("waiting for connection")
		conn, err := cf.Accept()
		if err != nil {
			log.Error("error", "error", err.Error())
			return
		}
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
				fmt.Println(string(buf[:n]))
				fmt.Print(">")
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
			_, err = conn.Write(line)
			if err != nil {
				log.Error("error", "error", err.Error())
				return
			}
		}
	}
}
