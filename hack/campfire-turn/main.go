package main

import (
	"fmt"
	"net"
	"strings"

	"github.com/pion/turn/v2"

	"github.com/webmeshproj/webmesh/hack/common"
	"github.com/webmeshproj/webmesh/pkg/campfire"
	"github.com/webmeshproj/webmesh/pkg/util"
)

func main() {
	log := common.ParseFlagsAndSetupLogger()
	loc, err := campfire.Find([]byte("LcNVwKd9qL4HFQ6lca2hB56W6DtDV9PS"), []string{"127.0.0.1:3478"})
	if err != nil {
		panic(err)
	}
	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	client, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: strings.TrimPrefix(loc.TURNServer, "turn:"),
		TURNServerAddr: strings.TrimPrefix(loc.TURNServer, "turn:"),
		Username:       loc.LocalUfrag(),
		Password:       loc.LocalPwd(),
		Realm:          "webmesh",
		Software:       campfire.Protocol,
		Conn:           conn,
		LoggerFactory:  util.NewSTUNLoggerFactory(log),
	})
	if err != nil {
		panic(err)
	}
	err = client.Listen()
	if err != nil {
		panic(err)
	}
	defer client.Close()
	err = client.CreatePermission(&net.UDPAddr{
		IP:   net.ParseIP("0.0.0.0"),
		Port: 0,
	})
	if err != nil {
		panic(err)
	}
	alloc, err := client.SendBindingRequest()
	if err != nil {
		panic(err)
	}
	fmt.Println(alloc)
	aconn, err := client.Allocate()
	if err != nil {
		panic(err)
	}
	defer aconn.Close()
}
