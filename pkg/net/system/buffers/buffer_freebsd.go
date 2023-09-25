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

package buffers

import (
	"context"
	"fmt"

	"github.com/webmeshproj/webmesh/pkg/common"
)

func setMaxReadBuffer(val int) error {
	// On darwin and BSD we need to add 15% to the value to account for
	// overhead.
	val = int(float64(val) * 1.15)
	return common.Exec(context.Background(), "sysctl", "-w", fmt.Sprintf("kern.ipc.maxsockbuf=%d", val))
}

func setMaxWriteBuffer(val int) error {
	// On darwin and BSD we need to add 15% to the value to account for
	// overhead.
	val = int(float64(val) * 1.15)
	return common.Exec(context.Background(), "sysctl", "-w", fmt.Sprintf("kern.ipc.maxsockbuf=%d", val))
}
