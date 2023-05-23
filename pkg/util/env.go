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

package util

import (
	"os"
	"strconv"
	"time"
)

// GetEnvDefault returns the value of an environment variable or a default value.
func GetEnvDefault(key, def string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return def
}

// GetEnvIntDefault returns the value of an environment variable or a default value.
func GetEnvIntDefault(key string, def int) int {
	if val := GetEnvDefault(key, strconv.Itoa(def)); val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return def
}

// GetEnvDurationDefault returns the value of an environment variable or a default value.
func GetEnvDurationDefault(key string, def time.Duration) time.Duration {
	if val := GetEnvDefault(key, def.String()); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			return d
		}
	}
	return def
}
