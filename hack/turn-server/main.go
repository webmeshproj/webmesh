package main

import (
	"github.com/webmeshproj/webmesh/hack/common"
	"github.com/webmeshproj/webmesh/pkg/services/turn"
)

func main() {
	common.ParseFlagsAndSetupLogger()
	srv, err := turn.NewServer(&turn.Options{
		PublicIP:         "127.0.0.1",
		ListenAddressUDP: "0.0.0.0",
		ListenPortUDP:    3478,
		PortRange:        "50000-60000",
		Realm:            "webmesh",
	})
	if err != nil {
		panic(err)
	}
	defer srv.Close()
	select {}
}
