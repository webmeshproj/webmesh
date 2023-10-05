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
	"strconv"

	"github.com/containernetworking/plugins/pkg/utils/sysctl"
)

func setMaxReadBuffer(val int) error {
	_, err := sysctl.Sysctl("net/core/rmem_max", strconv.Itoa(val))
	return err
}

func setMaxWriteBuffer(val int) error {
	_, err := sysctl.Sysctl("net/core/wmem_max", strconv.Itoa(val))
	return err
}
