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

package idauth

import (
	"context"
	"encoding/base64"
	"fmt"

	"google.golang.org/grpc"

	"github.com/webmeshproj/webmesh/pkg/crypto"
)

// NewCreds returns a DialOption that sets the basic auth credentials.
func NewCreds(key crypto.PrivateKey) grpc.DialOption {
	return grpc.WithPerRPCCredentials(&idauthCreds{
		key: key,
	})
}

type idauthCreds struct {
	key crypto.PrivateKey
}

func (c *idauthCreds) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	id := c.key.ID()
	sig, err := c.key.Sign([]byte(id))
	if err != nil {
		return nil, fmt.Errorf("failed to sign ID: %w", err)
	}
	encodedSig := base64.StdEncoding.EncodeToString(sig)
	return map[string]string{
		peerIDHeader:    id,
		signatureHeader: encodedSig,
	}, nil
}

func (c *idauthCreds) RequireTransportSecurity() bool {
	return false
}
