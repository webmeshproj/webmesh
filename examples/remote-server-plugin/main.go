// This is an example plugin that runs as a remote server. It registers to watch events
// from the Mesh and prints them to stdout.
package main

import (
	"context"
	"fmt"

	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/webmeshproj/node/pkg/meshdb"
	"github.com/webmeshproj/node/pkg/meshdb/peers"
	"github.com/webmeshproj/node/pkg/plugins"
	"github.com/webmeshproj/node/pkg/plugins/plugindb"
	"github.com/webmeshproj/node/pkg/version"
)

func main() {
	// Serve the plugin. This is a helper method that handles a simple insecure listener.
	// It is intended for plugins that are run as a separate executable on the node.
	// Plugins that run as servers should typically handle their own listener.
	plugins.Serve(context.Background(), &Plugin{
		closec: make(chan struct{}),
	})
}

// Plugin is an example plugin that prints events to stdout.
type Plugin struct {
	v1.UnimplementedPluginServer
	v1.UnimplementedWatchPluginServer
	// data is the meshdb database.
	data   meshdb.DB
	closec chan struct{}
}

// GetInfo must be implemented by all plugins. It returns information about the plugin
// and the capabilities it supports.
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

// Configure is called when the plugin is configured. It is called before any other
// methods are called. The configuration is passed in the req parameter as a mapstructure.
func (p *Plugin) Configure(ctx context.Context, req *v1.PluginConfiguration) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

// InjectQuerier can optionally be implemented by plugins that want to use the meshdb.
// It is called after Configure and before any other methods are called. The stream
// can be used with the plugindb package to open a database connection.
func (p *Plugin) InjectQuerier(srv v1.Plugin_InjectQuerierServer) error {
	db, err := plugindb.Open(srv)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	p.data = meshdb.New(db)
	select {
	case <-p.closec:
	case <-srv.Context().Done():
	}
	return nil
}

// Emit is called for Watch plugins when an event is emitted.
func (p *Plugin) Emit(ctx context.Context, ev *v1.Event) (*emptypb.Empty, error) {
	// The event will contain the event type and the node that it is about.
	fmt.Println(ev.String())
	// This is a redundant query as the event will contain the information.
	// However, we can demonstrate the injected querier here by looking up
	// the node that emitted the event.
	node, err := peers.New(p.data).Get(ctx, ev.GetNode().GetId())
	if err != nil {
		return nil, fmt.Errorf("get node: %w", err)
	}
	// Print the node details (they'll match those of the event).
	fmt.Printf("%+v\n", node)
	return &emptypb.Empty{}, nil
}

// Close is called when the plugin is shutting down.
func (p *Plugin) Close(context.Context, *emptypb.Empty) (*emptypb.Empty, error) {
	close(p.closec)
	return &emptypb.Empty{}, nil
}
