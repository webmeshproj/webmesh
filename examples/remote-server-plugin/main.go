// This is an example plugin that runs as a remote server. It registers to watch events
// from the Mesh and prints them to stdout.
package main

import (
	"context"
	"fmt"

	v1 "github.com/webmeshproj/api/go/v1"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/webmeshproj/webmesh/pkg/plugins"
	"github.com/webmeshproj/webmesh/pkg/plugins/plugindb"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
	"github.com/webmeshproj/webmesh/pkg/version"
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
	v1.UnimplementedStorageQuerierPluginServer
	// data is the meshdb database.
	data   storage.MeshDB
	closec chan struct{}
}

// GetInfo must be implemented by all plugins. It returns information about the plugin
// and the capabilities it supports.
func (p *Plugin) GetInfo(context.Context, *emptypb.Empty) (*v1.PluginInfo, error) {
	return &v1.PluginInfo{
		Name:        "stdout-watch",
		Version:     version.Version,
		Description: "Watch plugin that prints events to stdout",
		Capabilities: []v1.PluginInfo_PluginCapability{
			v1.PluginInfo_WATCH,
			v1.PluginInfo_STORAGE_QUERIER,
		},
	}, nil
}

// Configure is called when the plugin is configured. It is called before any other
// methods are called. The configuration is passed in the req parameter as a mapstructure.
func (p *Plugin) Configure(ctx context.Context, req *v1.PluginConfiguration) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

// Emit is called for Watch plugins when an event is emitted.
func (p *Plugin) Emit(ctx context.Context, ev *v1.Event) (*emptypb.Empty, error) {
	// The event will contain the event type and the node that it is about.
	fmt.Println(ev.String())
	// We can demonstrate usage of the injected meshdb here.
	peer, err := p.data.Peers().Get(ctx, types.NodeID(ev.GetNode().GetId()))
	if err != nil {
		return nil, err
	}
	fmt.Println(peer.String())
	return &emptypb.Empty{}, nil
}

// InjectQuerier can optionally be implemented by plugins that want to use the meshdb.
// It is called after Configure and before any other methods are called. The stream
// can be used with the plugindb package to open a database connection.
func (p *Plugin) InjectQuerier(srv v1.StorageQuerierPlugin_InjectQuerierServer) error {
	p.data = plugindb.OpenDB(srv)
	select {
	case <-p.closec:
	case <-srv.Context().Done():
	}
	return nil
}

// Close is called when the plugin is shutting down.
func (p *Plugin) Close(context.Context, *emptypb.Empty) (*emptypb.Empty, error) {
	close(p.closec)
	p.closec = make(chan struct{})
	return &emptypb.Empty{}, nil
}
