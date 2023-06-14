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

package streamlayer

import (
	"flag"
	"fmt"

	"github.com/webmeshproj/node/pkg/util"
)

const (
	ListenAddressEnvVar = "STORE_STREAM_LAYER_LISTEN_ADDRESS"
)

// Options are the StreamLayer options.
type Options struct {
	// ListenAddress is the address to listen on.
	ListenAddress string `yaml:"listen-address,omitempty" json:"listen-address,omitempty" toml:"listen-address,omitempty"`
}

// NewOptions returns new StreamLayerOptions with sensible defaults.
func NewOptions() *Options {
	return &Options{
		ListenAddress: ":9443",
	}
}

// BindFlags binds the StreamLayer options to the given flag set.
func (o *Options) BindFlags(fs *flag.FlagSet) {
	fs.StringVar(&o.ListenAddress, "store.stream-layer.listen-address", util.GetEnvDefault(ListenAddressEnvVar, ":9443"),
		"Stream layer listen address.")
}

// Validate validates the StreamLayer options.
func (o *Options) Validate() error {
	if o.ListenAddress == "" {
		return fmt.Errorf("listen address is required")
	}
	return nil
}
