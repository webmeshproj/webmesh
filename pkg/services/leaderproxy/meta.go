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

package leaderproxy

import (
	"context"

	"google.golang.org/grpc/metadata"
)

const (
	// PreferLeaderMeta is the metadata key for the Prefer-Leader header.
	PreferLeaderMeta = "x-webmesh-prefer-leader"
	// ProxiedFromMeta is the metadata key for the Proxied-From header.
	ProxiedFromMeta = "x-webmesh-proxied-from"
	// ProxiedForMeta is the metadata key for the Proxied-For header.
	ProxiedForMeta = "x-webmesh-proxied-for"
)

// HasPreferLeaderMeta returns true if the context has the Prefer-Leader header set to true.
func HasPreferLeaderMeta(ctx context.Context) bool {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return false
	}
	leaderPref := md.Get(PreferLeaderMeta)
	return len(leaderPref) > 0 && leaderPref[0] == "true"
}

// ProxiedFrom returns the node ID of the node that proxied the request.
// If the request was not proxied then false is returned.
func ProxiedFrom(ctx context.Context) (string, bool) {
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		proxiedFrom := md.Get(ProxiedFromMeta)
		if len(proxiedFrom) > 0 && proxiedFrom[0] != "" {
			return proxiedFrom[0], true
		}
	}
	return "", false
}

// ProxiedFor returns the node ID of the node that the request was proxied for.
// If the request was not proxied then false is returned.
func ProxiedFor(ctx context.Context) (string, bool) {
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		proxiedFor := md.Get(ProxiedForMeta)
		if len(proxiedFor) > 0 && proxiedFor[0] != "" {
			return proxiedFor[0], true
		}
	}
	return "", false
}
