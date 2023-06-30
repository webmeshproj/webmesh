// This is an example plugin that runs as a remote server. It registers to watch events
// from the Mesh and prints them to stdout.
package main

import (
	"context"
	"fmt"

	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/webmeshproj/node/pkg/plugins"
	"github.com/webmeshproj/node/pkg/version"
)

func main() {
	plugins.Serve(context.Background(), &Plugin{})
}

type Plugin struct {
	v1.UnimplementedPluginServer
	v1.UnimplementedWatchPluginServer
}

func (p *Plugin) GetInfo(context.Context, *emptypb.Empty) (*v1.PluginInfo, error) {
	return &v1.PluginInfo{
		Name:        "stdout-watch",
		Version:     version.Version,
		Description: "Watch plugin that prints events to stdout",
		Capabilities: []v1.PluginCapability{
			v1.PluginCapability_PLUGIN_CAPABILITY_WATCH,
		},
	}, nil
}

func (p *Plugin) Configure(ctx context.Context, req *v1.PluginConfiguration) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (p *Plugin) Emit(ctx context.Context, ev *v1.Event) (*emptypb.Empty, error) {
	fmt.Println(ev.String())
	return &emptypb.Empty{}, nil
}
