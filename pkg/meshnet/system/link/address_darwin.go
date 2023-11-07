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

package link

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/webmeshproj/webmesh/pkg/common"
)

// SetInterfaceAddress sets the address of the interface with the given name.
func SetInterfaceAddress(ctx context.Context, name string, addr netip.Prefix) error {
	if addr.Addr().Is4() {
		out, err := common.ExecOutput(ctx, "ifconfig", name, "inet", addr.String(), addr.Addr().String())
		if err != nil {
			if strings.Contains(string(out), "not exist") {
				return ErrLinkNotExists
			}
			return err
		}
		return nil
	}
	out, err := common.ExecOutput(ctx, "ifconfig", name, "inet6", addr.String(), "prefixlen", fmt.Sprintf("%d", addr.Bits()), "alias")
	if err != nil {
		if strings.Contains(string(out), "not exist") {
			return ErrLinkNotExists
		}
		return err
	}
	return nil
}

// RemoveInterfaceAddress removes the address of the interface with the given name.
func RemoveInterfaceAddress(_ context.Context, name string, addr netip.Prefix) error {
	return errors.New("not implemented")
}
