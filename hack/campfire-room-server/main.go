package main

import (
	"context"
	"flag"

	"github.com/webmeshproj/webmesh/pkg/mesh"
	"github.com/webmeshproj/webmesh/pkg/services/campfire"
	"github.com/webmeshproj/webmesh/pkg/util"
)

func main() {
	logLevel := flag.String("log-level", "info", "log level")
	flag.Parse()
	util.SetupLogging(*logLevel)
	mesh, err := mesh.NewTestMesh(context.Background())
	if err != nil {
		panic(err)
	}
	server := campfire.NewServer(mesh, &campfire.Options{
		ListenUDP: ":4095",
	})
	if err := server.ListenAndServe(context.Background()); err != nil {
		panic(err)
	}
}
