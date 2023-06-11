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

package ldap

import (
	"context"

	"google.golang.org/grpc"
)

// NewCreds returns a DialOption that sets the LDAP credentials.
func NewCreds(username, password string) grpc.DialOption {
	return grpc.WithPerRPCCredentials(&ldapCreds{
		username: username,
		password: password,
	})
}

type ldapCreds struct {
	username, password string
}

func (c *ldapCreds) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{
		usernameHeader: c.username,
		passwordHeader: c.password,
	}, nil
}

func (c *ldapCreds) RequireTransportSecurity() bool {
	return false
}
