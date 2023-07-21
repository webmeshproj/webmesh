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

// Package clients contains the interface for using plugin clients.
package clients

import (
	v1 "github.com/webmeshproj/api/v1"
)

// PluginClient is an extension of the interface for a plugin client.
// It provides methods for converting the client into other plugin clients.
type PluginClient interface {
	v1.PluginClient

	// Storage returns a storage client.
	Storage() v1.StoragePluginClient
	// Auth returns an auth client.
	Auth() v1.AuthPluginClient
	// Events returns an events client.
	Events() v1.WatchPluginClient
	// IPAM returns an IPAM client.
	IPAM() v1.IPAMPluginClient
}
