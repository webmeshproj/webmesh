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

package util

import (
	"fmt"
	"strconv"
	"strings"
)

// ParsePortRange parses a port range string.
func ParsePortRange(s string) (start int, end int, err error) {
	spl := strings.Split(s, "-")
	if len(spl) > 2 {
		return 0, 0, fmt.Errorf("invalid port range: %s", s)
	}
	start, err = strconv.Atoi(spl[0])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid port range: %s", s)
	}
	end = start
	if len(spl) == 2 {
		end, err = strconv.Atoi(spl[1])
		if err != nil {
			return 0, 0, fmt.Errorf("invalid port range: %s", s)
		}
	}
	return start, end, nil
}
