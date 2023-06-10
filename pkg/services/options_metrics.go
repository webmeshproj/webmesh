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

package services

import (
	"flag"

	"github.com/webmeshproj/node/pkg/util"
)

const (
	MetricsEnabledEnvVar       = "SERVICES_METRICS_ENABLED"
	MetricsListenAddressEnvVar = "SERVICES_METRICS_LISTEN_ADDRESS"
	MetricsPathEnvVar          = "SERVICES_METRICS_PATH"
)

// Metrics are options for exposing metrics.
type MetricsOptions struct {
	// Enabled is true if metrics should be enabled.
	Enabled bool `json:"enabled,omitempty" yaml:"enabled,omitempty" toml:"enabled,omitempty"`
	// MetricsListenAddress is the address to listen on for metrics.
	ListenAddress string `json:"listen-address,omitempty" yaml:"listen-address,omitempty" toml:"listen-address,omitempty"`
	// MetricsPath is the path to serve metrics on.
	Path string `json:"path,omitempty" yaml:"path,omitempty" toml:"path,omitempty"`
}

// NewMetricsOptions creates a new MetricsOptions with default values.
func NewMetricsOptions() *MetricsOptions {
	return &MetricsOptions{
		Enabled:       false,
		ListenAddress: ":8080",
		Path:          "/metrics",
	}
}

// BindFlags binds the flags.
func (o *MetricsOptions) BindFlags(fs *flag.FlagSet) {
	fs.BoolVar(&o.Enabled, "services.metrics.enabled", util.GetEnvDefault(MetricsEnabledEnvVar, "false") == "true",
		"Enable gRPC metrics.")
	fs.StringVar(&o.ListenAddress, "services.metrics.listen-address", util.GetEnvDefault(MetricsListenAddressEnvVar, ":8080"),
		"gRPC metrics listen address.")
	fs.StringVar(&o.Path, "services.metrics.path", util.GetEnvDefault(MetricsPathEnvVar, "/metrics"),
		"gRPC metrics path.")
}
