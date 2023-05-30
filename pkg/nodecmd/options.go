/*
Copyright 2023.

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

// Package nodecmd contains the entrypoint for webmesh nodes.
package nodecmd

import (
	"flag"

	"github.com/webmeshproj/node/pkg/global"
	"github.com/webmeshproj/node/pkg/services"
	"github.com/webmeshproj/node/pkg/store"
	"github.com/webmeshproj/node/pkg/store/streamlayer"
	"github.com/webmeshproj/node/pkg/wireguard"
)

// Options are the node options.
type Options struct {
	Global    *global.Options    `yaml:"global,omitempty" json:"global,omitempty" toml:"global,omitempty"`
	Store     *StoreOptions      `yaml:"store,omitempty" json:"store,omitempty" toml:"store,omitempty"`
	GRPC      *services.Options  `yaml:"grpc,omitempty" json:"grpc,omitempty" toml:"grpc,omitempty"`
	Wireguard *wireguard.Options `yaml:"wireguard,omitempty" json:"wireguard,omitempty" toml:"wireguard,omitempty"`
}

type StoreOptions struct {
	*store.Options `yaml:",inline" json:",inline" toml:",inline"`
	StreamLayer    *streamlayer.Options `yaml:"stream-layer,omitempty" json:"stream-layer,omitempty" toml:"stream-layer,omitempty"`
}

// BindFlags binds the flags.
func (o *Options) BindFlags(fs *flag.FlagSet) *Options {
	o.Global.BindFlags(fs)
	o.Store.BindFlags(fs)
	o.Store.StreamLayer.BindFlags(fs)
	o.GRPC.BindFlags(fs)
	o.Wireguard.BindFlags(fs)
	return o
}
