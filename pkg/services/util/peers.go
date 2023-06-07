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

// Package util contains common utilities for services.
package util

import (
	"context"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// PeerFromContext returns the peer ID from the context.
func PeerFromContext(ctx context.Context) (string, bool) {
	p, ok := peer.FromContext(ctx)
	if ok {
		if authInfo, ok := p.AuthInfo.(credentials.TLSInfo); ok {
			peerCerts := authInfo.State.PeerCertificates
			if len(peerCerts) > 0 {
				return peerCerts[0].Subject.CommonName, true
			}
		}
	}
	return "", false
}
