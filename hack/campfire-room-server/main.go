package main

import (
	"context"

	"github.com/webmeshproj/webmesh/hack/common"
	"github.com/webmeshproj/webmesh/pkg/mesh"
	"github.com/webmeshproj/webmesh/pkg/services/campfire"
)

func main() {
	common.ParseFlagsAndSetupLogger()
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
