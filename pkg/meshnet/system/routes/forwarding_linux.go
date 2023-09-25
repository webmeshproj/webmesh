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

package routes

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// EnableIPForwarding enables IP forwarding.
func EnableIPForwarding() error {
	on := []byte("1")
	mode := fs.FileMode(0644)
	errs := make([]error, 0, 3)
	err := os.WriteFile("/proc/sys/net/ipv4/conf/all/forwarding", on, mode)
	if err != nil {
		errs = append(errs, fmt.Errorf("write net.ipv4.conf.all.forwarding: %w", err))
	}
	// Write to the legacy configuration file
	err = os.WriteFile("/proc/sys/net/ipv4/ip_forward", on, mode)
	if err != nil {
		errs = append(errs, fmt.Errorf("write net.ipv4.ip_forward: %w", err))
	}
	err = os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", on, mode)
	if err != nil {
		errs = append(errs, fmt.Errorf("write net.ipv6.conf.all.forwarding: %w", err))
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}
