package main

import (
	"flag"
	"os"

	"github.com/webmeshproj/webmesh/hack/common"
	"github.com/webmeshproj/webmesh/pkg/campfire"
	"github.com/webmeshproj/webmesh/pkg/services/turn"
)

func main() {
	psk := flag.String("psk", "", "pre-shared key")
	turnServer := flag.String("turn", "127.0.0.1:3478", "TURN server")
	log := common.ParseFlagsAndSetupLogger()

	if *psk == "" {
		log.Error("PSK must not be empty")
		os.Exit(1)
	}
	if *turnServer == "" {
		log.Error("TURN server must not be empty")
		os.Exit(1)
	}
	loc, err := campfire.Find([]byte(*psk), []string{*turnServer})
	if err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}
	cli, err := turn.NewCampfireClient(turn.CampfireClientOptions{
		Addr:  loc.TURNServer,
		Ufrag: loc.LocalUfrag(),
		Pwd:   loc.LocalPwd(),
	})
	if err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}
	defer cli.Close()

	err = cli.Announce(loc.RemoteUfrag(), loc.RemotePwd())
	if err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}

	for offer := range cli.Offers() {
		log.Info("Received offer", "offer", offer)
	}
}
