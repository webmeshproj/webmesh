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
	"time"

	"google.golang.org/grpc"

	"github.com/webmeshproj/webmesh/pkg/crypto"
)

// NewCreds returns a DialOption that sets the ID auth credentials.
func NewCreds(key crypto.PrivateKey) grpc.DialOption {
	return grpc.WithPerRPCCredentials(&idauthCreds{
		key: key,
	})
}

// NewAuthSignature returns a signature for the given key and the current
// time. The returned signature is base64 encoded.
func NewAuthSignature(key crypto.PrivateKey) (string, error) {
	return newAuthSignatureWithTime(key, Now())
}

// MustNewAuthSignature is like NewAuthSignature but panics on error.
func MustNewAuthSignature(key crypto.PrivateKey) string {
	sig, err := NewAuthSignature(key)
	if err != nil {
		panic(err)
	}
	return sig
}

func mustNewAuthSignatureWithTime(key crypto.PrivateKey, t time.Time) string {
	sig, err := newAuthSignatureWithTime(key, t)
	if err != nil {
		panic(err)
	}
	return sig
}

func newAuthSignatureWithTime(key crypto.PrivateKey, t time.Time) (string, error) {
	ts := t.Truncate(time.Second * 30).Unix()
	sig, err := key.AsIdentity().Sign([]byte(fmt.Sprintf("%s:%d", key.ID(), ts)))
	if err != nil {
		return "", fmt.Errorf("failed to sign ID: %w", err)
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

type idauthCreds struct {
	key crypto.PrivateKey
}

func (c *idauthCreds) RequireTransportSecurity() bool {
	return false
}

func (c *idauthCreds) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return c.newMetadata()
}

func (c *idauthCreds) newMetadata() (map[string]string, error) {
	sig, err := NewAuthSignature(c.key)
	if err != nil {
		return nil, fmt.Errorf("failed to sign ID: %w", err)
	}
	return map[string]string{
		peerIDHeader:    c.key.ID(),
		signatureHeader: sig,
	}, nil
}
