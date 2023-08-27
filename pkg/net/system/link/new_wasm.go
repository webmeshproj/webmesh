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
	"errors"

	"github.com/webmeshproj/webmesh/pkg/context"
)

// NewKernel creates a new kernel WireGuard interface on the host system with the given name.
func NewKernel(ctx context.Context, name string, mtu uint32) error {
	return errors.New("kernel interfaces not supported on wasm")
}

// NewTUN creates a new WireGuard interface using the userspace tun driver.
func NewTUN(ctx context.Context, name string, mtu uint32) (realName string, closer func(), err error) {
	return "", nil, errors.New("tun interfaces not supported on wasm")
}
