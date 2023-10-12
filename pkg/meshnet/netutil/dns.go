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

package netutil

import (
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/webmeshproj/webmesh/pkg/context"
)

// ResolveTCPAddr resolves a TCP address with retries and context.
func ResolveTCPAddr(ctx context.Context, lookup string, maxRetries int) (net.Addr, error) {
	var addr net.Addr
	var err error
	var tries int
	for tries < maxRetries {
		addr, err = net.ResolveTCPAddr("tcp", lookup)
		if err != nil {
			tries++
			err = fmt.Errorf("resolve tcp address: %w", err)
			context.LoggerFrom(ctx).Error("failed to resolve advertise address", slog.String("error", err.Error()))
			if tries < maxRetries {
				select {
				case <-ctx.Done():
					return nil, fmt.Errorf("%w: %w", err, ctx.Err())
				case <-time.After(time.Second * 1):
					continue
				}
			}
		}
		break
	}
	return addr, err
}
