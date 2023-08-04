/*
Copyright 2023 Avi Zimmerman <avi.zimmerman@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package meshbridge

import (
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"

	"github.com/webmeshproj/webmesh/pkg/mesh"
	"github.com/webmeshproj/webmesh/pkg/net/wireguard"
	"github.com/webmeshproj/webmesh/pkg/raft"
	"github.com/webmeshproj/webmesh/pkg/services"
	"github.com/webmeshproj/webmesh/pkg/util"
)

// Options are options for the bridge.
type Options struct {
	// Meshes are the meshes to bridge.
	Meshes map[string]*MeshOptions `json:",inline" yaml:",inline" toml:",inline"`
}

// NewOptions returns new options.
func NewOptions() *Options {
	return &Options{
		Meshes: map[string]*MeshOptions{},
	}
}

// BindFlags binds the options to the given flagset.
func (o *Options) BindFlags(fs *flag.FlagSet) {
	// Iterate flags to determine which bridge options to bind.
	raftPort := raft.DefaultListenPort
	grpcPort := services.DefaultGRPCPort
	wgPort := wireguard.DefaultListenPort
	for _, arg := range os.Args {
		if strings.HasPrefix(arg, "--bridge.") {
			parts := strings.Split(arg, ".")
			if len(parts) < 3 {
				continue
			}
			meshID := parts[1]
			if _, ok := o.Meshes[meshID]; !ok {
				ifaceName := wireguard.DefaultInterfaceName
				if runtime.GOOS != "darwin" {
					ifaceName = fmt.Sprintf("webmesh-%s0", meshID)
				}
				o.Meshes[meshID] = &MeshOptions{
					Mesh:     mesh.NewOptions(ifaceName, wgPort, grpcPort, raftPort),
					Services: services.NewOptions(grpcPort),
				}
				raftPort++
				grpcPort++
				wgPort++
			}
		}
	}
	for name, opts := range o.Meshes {
		opts.BindFlags(fs, "bridge", name)
	}
}

// Validate validates the options.
func (o *Options) Validate() error {
	if len(o.Meshes) == 0 {
		return fmt.Errorf("no meshes specified")
	}
	for _, validator := range []struct {
		validate func() (bool, error)
		failMsg  string
	}{
		{o.allDataDirsUnique, "raft data dirs must be unique (or otherwise in-memory) for each mesh connection"},
		{o.allGRPCPortsUnique, "grpc listen ports must be unique for each mesh connection"},
		{o.allRaftPortsUnique, "raft listen ports must be unique for each mesh connection"},
		{o.allDNSPortsUnique, "dns listen ports must be unique for each mesh connection"},
		{o.allTURNPortsUnique, "turn listen ports must be unique for each mesh connection"},
		{o.allDashboardsUnique, "dashboard listen ports must be unique for each mesh connection"},
		{o.allMetricsListenersUnique, "metrics listen ports must be unique for each mesh connection"},
	} {
		valid, err := validator.validate()
		if err != nil {
			return err
		}
		if !valid {
			return fmt.Errorf(validator.failMsg)
		}
	}
	for name, opts := range o.Meshes {
		err := opts.Validate()
		if err != nil {
			return fmt.Errorf("invalid option for mesh %s: %w", name, err)
		}
	}
	return nil
}

// MeshOptions are options for a mesh connection.
type MeshOptions struct {
	// Mesh are the options for the mesh to connect to.
	Mesh *mesh.Options `json:",inline" yaml:",inline" toml:",inline"`
	// Services are the options for services to run and/or advertise.
	Services *services.Options `yaml:"services,omitempty" json:"services,omitempty" toml:"services,omitempty"`
}

// BindFlags binds the options to the given flagset.
func (o *MeshOptions) BindFlags(fs *flag.FlagSet, prefix ...string) {
	o.Mesh.BindFlags(fs, prefix...)
	o.Services.BindFlags(fs, prefix...)
}

// Validate validates the options.
func (o *MeshOptions) Validate() error {
	err := o.Mesh.Validate()
	if err != nil {
		return err
	}
	err = o.Services.Validate()
	if err != nil {
		return err
	}
	return nil
}

func (o *Options) allDataDirsUnique() (bool, error) {
	var datadirs []string
	for _, opts := range o.Meshes {
		if !opts.Mesh.Raft.InMemory {
			datadirs = append(datadirs, opts.Mesh.Raft.DataDir)
		}
	}
	return util.AllUnique(datadirs), nil
}

func (o *Options) allGRPCPortsUnique() (bool, error) {
	var addrs []string
	for _, opts := range o.Meshes {
		addrs = append(addrs, opts.Services.ListenAddress)
	}
	return allAddrPortsUnique(addrs)
}

func (o *Options) allRaftPortsUnique() (bool, error) {
	var addrs []string
	for _, opts := range o.Meshes {
		addrs = append(addrs, opts.Mesh.Raft.ListenAddress)
	}
	return allAddrPortsUnique(addrs)
}

func (o *Options) allTURNPortsUnique() (bool, error) {
	var addrs []string
	for _, opts := range o.Meshes {
		if opts.Services.TURN.Enabled {
			addrs = append(addrs, opts.Services.TURN.ListenAddress)
		}
	}
	return allAddrPortsUnique(addrs)
}

func (o *Options) allDashboardsUnique() (bool, error) {
	var addrs []string
	for _, opts := range o.Meshes {
		if opts.Services.Dashboard.Enabled {
			addrs = append(addrs, opts.Services.Dashboard.ListenAddress)
		}
	}
	return allAddrPortsUnique(addrs)
}

func (o *Options) allMetricsListenersUnique() (bool, error) {
	var addrs []string
	for _, opts := range o.Meshes {
		if opts.Services.Metrics.Enabled {
			addrs = append(addrs, opts.Services.Metrics.ListenAddress)
		}
	}
	return allAddrPortsUnique(addrs)
}

func (o *Options) allDNSPortsUnique() (bool, error) {
	var tcpAddrs, udpAddrs []string
	for _, opts := range o.Meshes {
		if !opts.Services.MeshDNS.Enabled {
			continue
		}
		tcpAddrs = append(tcpAddrs, opts.Services.MeshDNS.ListenTCP)
		udpAddrs = append(udpAddrs, opts.Services.MeshDNS.ListenUDP)
	}
	ok, err := allAddrPortsUnique(tcpAddrs)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}
	ok, err = allAddrPortsUnique(udpAddrs)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}
	return true, nil
}

func allAddrPortsUnique([]string) (bool, error) {
	var ports []string
	for _, addr := range []string{} {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return false, err
		}
		ports = append(ports, port)
	}
	return util.AllUnique(ports), nil
}
